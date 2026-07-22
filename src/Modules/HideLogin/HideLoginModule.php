<?php
/**
 * Core module: hide the login URL and block wp-login.php / wp-admin.
 *
 * The request-interception logic in this file is derived from "WPS Hide Login"
 * (GPLv2 or later) by WPServeur, NicolasKulka and wpformation, and adapted for
 * Datametric Login Shield. See readme.txt "Credits".
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Modules\HideLogin;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use Datametric\LoginShield\Container;
use Datametric\LoginShield\Contracts\ModuleInterface;
use Datametric\LoginShield\Support\Options;

/**
 * Intercepts login/admin requests to enforce the custom login slug.
 *
 * IMPORTANT: this is the ONLY module allowed to manipulate $pagenow and the
 * $_SERVER superglobals. Other modules must hook the filters this class exposes.
 */
class HideLoginModule implements ModuleInterface {

	/**
	 * Whether the current request is the (now hidden) wp-login.php.
	 *
	 * @var bool
	 */
	private $wp_login_php;

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'hide-login';
	}

	/**
	 * {@inheritDoc}
	 */
	public function is_pro() {
		return false;
	}

	/**
	 * Register services in the container.
	 *
	 * @param Container $container Shared service container.
	 *
	 * @return void
	 */
	public function register( Container $container ) {
		// Expose helpers to other modules / the admin screen.
		$container->set( 'hide_login', $this );
	}

	/**
	 * {@inheritDoc}
	 */
	public function boot() {
		global $wp_version;

		if ( version_compare( $wp_version, '4.0-RC1-src', '<' ) ) {
			add_action( 'admin_notices', array( $this, 'admin_notices_incompatible' ) );
			add_action( 'network_admin_notices', array( $this, 'admin_notices_incompatible' ) );

			return;
		}

		if ( ( is_multisite() && ! function_exists( 'is_plugin_active_for_network' ) ) || ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if ( is_plugin_active_for_network( 'rename-wp-login/rename-wp-login.php' ) ) {
			deactivate_plugins( DMLS_BASENAME );
			add_action( 'network_admin_notices', array( $this, 'admin_notices_plugin_conflict' ) );
			if ( isset( $_GET['activate'] ) ) {
				unset( $_GET['activate'] );
			}

			return;
		}

		if ( is_plugin_active( 'rename-wp-login/rename-wp-login.php' ) ) {
			deactivate_plugins( DMLS_BASENAME );
			add_action( 'admin_notices', array( $this, 'admin_notices_plugin_conflict' ) );
			if ( isset( $_GET['activate'] ) ) {
				unset( $_GET['activate'] );
			}

			return;
		}

		if ( is_multisite() && is_plugin_active_for_network( DMLS_BASENAME ) ) {
			add_action( 'wpmu_options', array( $this, 'wpmu_options' ) );
			add_action( 'update_wpmu_options', array( $this, 'update_wpmu_options' ) );

			add_filter(
				'network_admin_plugin_action_links_' . DMLS_BASENAME,
				array( $this, 'plugin_action_links' )
			);
		}

		if ( is_multisite() ) {
			add_action( 'wp_before_admin_bar_render', array( $this, 'modify_mysites_menu' ), 999 );
		}

		add_action( 'plugins_loaded', array( $this, 'plugins_loaded' ), 9999 );
		add_action( 'init', array( $this, 'init_block_access' ) );
		add_action( 'wp_loaded', array( $this, 'wp_loaded' ) );
		add_action( 'setup_theme', array( $this, 'setup_theme' ), 1 );

		add_filter( 'plugin_action_links_' . DMLS_BASENAME, array( $this, 'plugin_action_links' ) );
		add_filter( 'site_url', array( $this, 'site_url' ), 10, 4 );
		add_filter( 'network_site_url', array( $this, 'network_site_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( $this, 'wp_redirect' ), 10, 2 );
		add_filter( 'site_option_welcome_email', array( $this, 'welcome_email' ) );

		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );

		add_action( 'template_redirect', array( $this, 'redirect_export_data' ) );
		add_filter( 'login_url', array( $this, 'login_url' ), 10, 3 );

		add_filter( 'user_request_action_email_content', array( $this, 'user_request_action_email_content' ), 999, 2 );
		add_filter( 'site_status_tests', array( $this, 'site_status_tests' ) );

		add_filter( 'manage_sites_action_links', array( $this, 'manage_sites_action_links' ), 10, 3 );

		// Redirect the legacy WPS Hide Login settings anchor to our own page.
		add_action( 'admin_init', array( $this, 'legacy_settings_redirect' ) );
	}

	/**
	 * Disable the loopback-request test that would hit the hidden login URL.
	 *
	 * @param array $tests Site Health tests.
	 *
	 * @return array
	 */
	public function site_status_tests( $tests ) {
		unset( $tests['async']['loopback_requests'] );

		return $tests;
	}

	/**
	 * Rewrite the login slug inside user data-request confirmation emails.
	 *
	 * @param string $email_text Email body.
	 * @param array  $email_data Email data.
	 *
	 * @return string
	 */
	public function user_request_action_email_content( $email_text, $email_data ) {
		$email_text = str_replace(
			'###CONFIRM_URL###',
			esc_url_raw( str_replace( $this->new_login_slug() . '/', 'wp-login.php', $email_data['confirm_url'] ) ),
			$email_text
		);

		return $email_text;
	}

	/**
	 * Whether the permalink structure uses trailing slashes.
	 *
	 * @return bool
	 */
	private function use_trailing_slashes() {
		return ( '/' === substr( get_option( 'permalink_structure' ), -1, 1 ) );
	}

	/**
	 * Safely read and sanitize the request URI (used only for routing/compares).
	 *
	 * @return string
	 */
	private function request_uri() {
		return isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
	}

	/**
	 * Safely read and sanitize the query string.
	 *
	 * @return string
	 */
	private function query_string() {
		return isset( $_SERVER['QUERY_STRING'] ) ? sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '';
	}

	/**
	 * Apply (or strip) a trailing slash to match the permalink structure.
	 *
	 * @param string $string URL or path.
	 *
	 * @return string
	 */
	private function user_trailingslashit( $string ) {
		return $this->use_trailing_slashes() ? trailingslashit( $string ) : untrailingslashit( $string );
	}

	/**
	 * Load the theme template for the hidden login request.
	 *
	 * @return void
	 */
	private function wp_template_loader() {
		global $pagenow;

		$pagenow = 'index.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- deliberately reroutes the request to hide the login page.

		if ( ! defined( 'WP_USE_THEMES' ) ) {
			define( 'WP_USE_THEMES', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- WP core constant, intentionally set.
		}

		wp();

		require_once ABSPATH . WPINC . '/template-loader.php';

		die;
	}

	/**
	 * Rewrite admin-bar "My Sites" links for multisite.
	 *
	 * @return void
	 */
	public function modify_mysites_menu() {
		global $wp_admin_bar;

		$all_toolbar_nodes = $wp_admin_bar->get_nodes();

		foreach ( $all_toolbar_nodes as $node ) {
			if ( preg_match( '/^blog-(\d+)(.*)/', $node->id, $matches ) ) {
				$blog_id    = $matches[1];
				$login_slug = $this->new_login_slug( $blog_id );
				if ( $login_slug ) {
					if ( ! $matches[2] || '-d' === $matches[2] ) {
						$args       = $node;
						$old_href   = $args->href;
						$args->href = preg_replace( '/wp-admin\/$/', "$login_slug/", $old_href );
						if ( $old_href !== $args->href ) {
							$wp_admin_bar->add_node( $args );
						}
					} elseif ( strpos( $node->href, '/wp-admin/' ) !== false ) {
						$wp_admin_bar->remove_node( $node->id );
					}
				}
			}
		}
	}

	/**
	 * Resolve the login slug (optionally for a specific multisite blog).
	 *
	 * @param string|int $blog_id Optional blog id.
	 *
	 * @return string|false
	 */
	private function new_login_slug( $blog_id = '' ) {
		if ( $blog_id ) {
			return get_blog_option( $blog_id, 'whl_page' );
		}

		return Options::login_slug();
	}

	/**
	 * Resolve the redirect slug.
	 *
	 * @return string
	 */
	private function new_redirect_slug() {
		return Options::redirect_slug();
	}

	/**
	 * Build the full custom login URL.
	 *
	 * @param string|null $scheme URL scheme.
	 *
	 * @return string
	 */
	public function new_login_url( $scheme = null ) {
		$url = apply_filters( 'dmls_home_url', home_url( '/', $scheme ) );

		if ( get_option( 'permalink_structure' ) ) {
			return $this->user_trailingslashit( $url . $this->new_login_slug() );
		}

		return $url . '?' . $this->new_login_slug();
	}

	/**
	 * Build the redirect URL used for blocked admin/login access.
	 *
	 * @param string|null $scheme URL scheme.
	 *
	 * @return string
	 */
	public function new_redirect_url( $scheme = null ) {
		if ( get_option( 'permalink_structure' ) ) {
			return $this->user_trailingslashit( home_url( '/', $scheme ) . $this->new_redirect_slug() );
		}

		return home_url( '/', $scheme ) . '?' . $this->new_redirect_slug();
	}

	/**
	 * Notice: WordPress too old.
	 *
	 * @return void
	 */
	public function admin_notices_incompatible() {
		echo '<div class="error notice is-dismissible"><p>' . esc_html__( 'Please upgrade to the latest version of WordPress to activate', 'datametric-login-shield' ) . ' <strong>' . esc_html__( 'Datametric Login Shield', 'datametric-login-shield' ) . '</strong>.</p></div>';
	}

	/**
	 * Notice: conflicting plugin active.
	 *
	 * @return void
	 */
	public function admin_notices_plugin_conflict() {
		echo '<div class="error notice is-dismissible"><p>' . esc_html__( 'Datametric Login Shield could not be activated because you already have Rename wp-login.php active. Please uninstall Rename wp-login.php to use Datametric Login Shield.', 'datametric-login-shield' ) . '</p></div>';
	}

	/**
	 * Network settings: render the network default fields.
	 *
	 * @return void
	 */
	public function wpmu_options() {
		$out = '';

		$out .= '<h3>' . esc_html__( 'Datametric Login Shield', 'datametric-login-shield' ) . '</h3>';
		$out .= '<p>' . esc_html__( 'This option allows you to set a networkwide default, which can be overridden by individual sites.', 'datametric-login-shield' ) . '</p>';
		$out .= '<table class="form-table">';
		$out .= '<tr valign="top">';
		$out .= '<th scope="row"><label for="whl_page">' . esc_html__( 'Networkwide default', 'datametric-login-shield' ) . '</label></th>';
		$out .= '<td><input id="whl_page" type="text" name="whl_page" value="' . esc_attr( get_site_option( 'whl_page', 'login' ) ) . '"></td>';
		$out .= '<th scope="row"><label for="whl_redirect_admin">' . esc_html__( 'Redirection url default', 'datametric-login-shield' ) . '</label></th>';
		$out .= '<td><input id="whl_redirect_admin" type="text" name="whl_redirect_admin" value="' . esc_attr( get_site_option( 'whl_redirect_admin', '404' ) ) . '"></td>';
		$out .= '</tr>';
		$out .= '</table>';

		echo $out; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts above.
	}

	/**
	 * Network settings: persist the network default fields.
	 *
	 * @return void
	 */
	public function update_wpmu_options() {
		if ( empty( $_POST ) ) {
			return;
		}

		check_admin_referer( 'siteoptions' );

		if ( isset( $_POST['whl_page'] ) ) {
			$whl_page = sanitize_title_with_dashes( wp_unslash( $_POST['whl_page'] ) );

			if ( $whl_page && false === strpos( $whl_page, 'wp-login' ) && ! in_array( $whl_page, $this->forbidden_slugs(), true ) ) {
				update_site_option( 'whl_page', $whl_page );
				flush_rewrite_rules( true );
			}
		}

		if ( isset( $_POST['whl_redirect_admin'] ) ) {
			$whl_redirect_admin = sanitize_title_with_dashes( wp_unslash( $_POST['whl_redirect_admin'] ) );

			if ( $whl_redirect_admin && false === strpos( $whl_redirect_admin, '404' ) ) {
				update_site_option( 'whl_redirect_admin', $whl_redirect_admin );
				flush_rewrite_rules( true );
			}
		}
	}

	/**
	 * Add a "Settings" action link to our own page.
	 *
	 * @param array $links Existing action links.
	 *
	 * @return array
	 */
	public function plugin_action_links( $links ) {
		if ( is_network_admin() && is_plugin_active_for_network( DMLS_BASENAME ) ) {
			array_unshift( $links, '<a href="' . esc_url( network_admin_url( 'settings.php' ) ) . '">' . esc_html__( 'Settings', 'datametric-login-shield' ) . '</a>' );
		} else {
			array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=datametric-login-shield' ) ) . '">' . esc_html__( 'Settings', 'datametric-login-shield' ) . '</a>' );
		}

		return $links;
	}

	/**
	 * Preserve export-data confirmation links through the hidden login URL.
	 *
	 * @return void
	 */
	public function redirect_export_data() {
		// Public, key-validated confirmation link (no nonce by design; verified via wp_validate_user_request_key()).
		if ( ! empty( $_GET ) && isset( $_GET['action'], $_GET['request_id'], $_GET['confirm_key'] ) && 'confirmaction' === sanitize_key( wp_unslash( $_GET['action'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$request_id = (int) wp_unslash( $_GET['request_id'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$key        = sanitize_text_field( wp_unslash( $_GET['confirm_key'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$result     = wp_validate_user_request_key( $request_id, $key );
			if ( ! is_wp_error( $result ) ) {
				wp_safe_redirect(
					add_query_arg(
						array(
							'action'      => 'confirmaction',
							'request_id'  => $request_id,
							'confirm_key' => rawurlencode( $key ),
						),
						$this->new_login_url()
					)
				);
				exit();
			}
		}
	}

	/**
	 * Intercept the request very early to hide wp-login.php / expose the slug.
	 *
	 * @return void
	 */
	public function plugins_loaded() {
		global $pagenow;

		$request = wp_parse_url( rawurldecode( $this->request_uri() ) );

		if ( ( strpos( rawurldecode( $this->request_uri() ), 'wp-login.php' ) !== false
				|| ( isset( $request['path'] ) && untrailingslashit( $request['path'] ) === site_url( 'wp-login', 'relative' ) ) )
			&& ! is_admin() ) {

			$this->wp_login_php = true;

			$_SERVER['REQUEST_URI'] = $this->user_trailingslashit( '/' . str_repeat( '-/', 10 ) );

			$pagenow = 'index.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- deliberately reroutes the request to hide the login page.

		} elseif ( ( isset( $request['path'] ) && untrailingslashit( $request['path'] ) === home_url( $this->new_login_slug(), 'relative' ) )
			|| ( ! get_option( 'permalink_structure' )
				&& isset( $_GET[ $this->new_login_slug() ] )
				&& empty( $_GET[ $this->new_login_slug() ] ) ) ) {

			$_SERVER['SCRIPT_NAME'] = $this->new_login_slug();

			$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- deliberately reroutes the request to the hidden login page.

		} elseif ( ( strpos( rawurldecode( $this->request_uri() ), 'wp-register.php' ) !== false
				|| ( isset( $request['path'] ) && untrailingslashit( $request['path'] ) === site_url( 'wp-register', 'relative' ) ) )
			&& ! is_admin() ) {

			$this->wp_login_php = true;

			$_SERVER['REQUEST_URI'] = $this->user_trailingslashit( '/' . str_repeat( '-/', 10 ) );

			$pagenow = 'index.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- deliberately reroutes the request to hide the login page.
		}
	}

	/**
	 * Block the Customizer for logged-out users on the hidden setup.
	 *
	 * @return void
	 */
	public function setup_theme() {
		global $pagenow;

		if ( ! is_user_logged_in() && 'customize.php' === $pagenow ) {
			wp_die( esc_html__( 'This has been disabled', 'datametric-login-shield' ), 403 );
		}
	}

	/**
	 * The core redirect/serve logic once WordPress has loaded.
	 *
	 * @return void
	 */
	public function wp_loaded() {
		global $pagenow;

		$request = wp_parse_url( rawurldecode( $this->request_uri() ) );

		/**
		 * Fires before Login Shield decides how to handle the request.
		 *
		 * @param array $request Parsed request URL parts.
		 */
		do_action( 'dmls_before_redirect', $request );

		if ( ! ( isset( $_GET['action'] ) && 'postpass' === sanitize_key( wp_unslash( $_GET['action'] ) ) && isset( $_POST['post_password'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing

			if ( is_admin() && ! is_user_logged_in() && ! defined( 'WP_CLI' ) && ! defined( 'DOING_AJAX' ) && ! defined( 'DOING_CRON' ) && 'admin-post.php' !== $pagenow && ( ! isset( $request['path'] ) || '/wp-admin/options.php' !== $request['path'] ) ) {
				wp_safe_redirect( $this->new_redirect_url() );
				die();
			}

			if ( ! is_user_logged_in() && isset( $_GET['wc-ajax'] ) && 'profile.php' === $pagenow ) {
				wp_safe_redirect( $this->new_redirect_url() );
				die();
			}

			if ( ! is_user_logged_in() && isset( $request['path'] ) && '/wp-admin/options.php' === $request['path'] ) {
				header( 'Location: ' . $this->new_redirect_url() );
				die;
			}

			if ( 'wp-login.php' === $pagenow && isset( $request['path'] ) && $request['path'] !== $this->user_trailingslashit( $request['path'] ) && get_option( 'permalink_structure' ) ) {
				wp_safe_redirect(
					$this->user_trailingslashit( $this->new_login_url() )
					. ( ! empty( $this->query_string() ) ? '?' . $this->query_string() : '' )
				);

				die;

			} elseif ( $this->wp_login_php ) {

				$referer = wp_get_referer();

				if ( $referer && false !== strpos( $referer, 'wp-activate.php' ) ) {
					$referer = wp_parse_url( $referer );

					if ( ! empty( $referer['query'] ) ) {
						parse_str( $referer['query'], $referer );

						require_once WPINC . '/ms-functions.php';

						if ( ! empty( $referer['key'] ) ) {
							$result = wpmu_activate_signup( $referer['key'] );

							if ( is_wp_error( $result )
								&& ( 'already_active' === $result->get_error_code()
									|| 'blog_taken' === $result->get_error_code() ) ) {

								wp_safe_redirect(
									$this->new_login_url()
									. ( ! empty( $this->query_string() ) ? '?' . $this->query_string() : '' )
								);

								die;
							}
						}
					}
				}

				$this->wp_template_loader();

			} elseif ( 'wp-login.php' === $pagenow ) {
				global $error, $interim_login, $action, $user_login;

				$redirect_to = admin_url();

				$requested_redirect_to = '';
				if ( isset( $_REQUEST['redirect_to'] ) ) {
					$requested_redirect_to = esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				}

				if ( is_user_logged_in() ) {
					$user = wp_get_current_user();
					if ( ! isset( $_REQUEST['action'] ) ) {
						$logged_in_redirect = apply_filters( 'dmls_logged_in_redirect', $redirect_to, $requested_redirect_to, $user );
						wp_safe_redirect( $logged_in_redirect );
						die();
					}
				}

				@require_once ABSPATH . 'wp-login.php';

				die;
			}
		}
	}

	/**
	 * Filter site_url for wp-login.php.
	 *
	 * @param string $url     URL.
	 * @param string $path    Path.
	 * @param string $scheme  Scheme.
	 * @param int    $blog_id Blog id.
	 *
	 * @return string
	 */
	public function site_url( $url, $path, $scheme, $blog_id ) {
		return $this->filter_wp_login_php( $url, $scheme );
	}

	/**
	 * Filter network_site_url for wp-login.php.
	 *
	 * @param string $url    URL.
	 * @param string $path   Path.
	 * @param string $scheme Scheme.
	 *
	 * @return string
	 */
	public function network_site_url( $url, $path, $scheme ) {
		return $this->filter_wp_login_php( $url, $scheme );
	}

	/**
	 * Filter wp_redirect targets pointing at wp-login.php.
	 *
	 * @param string $location Target URL.
	 * @param int    $status   HTTP status.
	 *
	 * @return string
	 */
	public function wp_redirect( $location, $status ) {
		if ( strpos( $location, 'https://wordpress.com/wp-login.php' ) !== false ) {
			return $location;
		}

		return $this->filter_wp_login_php( $location );
	}

	/**
	 * Rewrite wp-login.php URLs to the hidden login URL.
	 *
	 * @param string      $url    URL to filter.
	 * @param string|null $scheme Scheme.
	 *
	 * @return string
	 */
	public function filter_wp_login_php( $url, $scheme = null ) {
		global $pagenow;

		$origin_url = $url;

		if ( strpos( $url, 'wp-login.php?action=postpass' ) !== false ) {
			return $url;
		}

		if ( is_multisite() && 'install.php' === $pagenow ) {
			return $url;
		}

		if ( strpos( $url, 'wp-login.php' ) !== false && strpos( (string) wp_get_referer(), 'wp-login.php' ) === false ) {

			if ( is_ssl() ) {
				$scheme = 'https';
			}

			$args = explode( '?', $url );

			if ( isset( $args[1] ) ) {

				parse_str( $args[1], $args );

				if ( isset( $args['login'] ) ) {
					$args['login'] = rawurlencode( $args['login'] );
				}

				$url = add_query_arg( $args, $this->new_login_url( $scheme ) );

			} else {

				$url = $this->new_login_url( $scheme );
			}
		}

		if ( isset( $_POST['post_password'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			global $current_user;
			$posted_password = wp_unslash( $_POST['post_password'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- a password must not be altered.
			if ( ! is_user_logged_in() && is_wp_error( wp_authenticate_username_password( null, $current_user->user_login, $posted_password ) ) ) {
				return $origin_url;
			}
		}

		if ( ! is_user_logged_in() ) {
			if ( file_exists( WP_CONTENT_DIR . '/plugins/gravityforms/gravityforms.php' ) && isset( $_GET['gf_page'] ) ) {
				return $origin_url;
			}
		}

		return $url;
	}

	/**
	 * Rewrite the login slug inside the multisite welcome email.
	 *
	 * @param string $value Email content.
	 *
	 * @return string
	 */
	public function welcome_email( $value ) {
		return str_replace( 'wp-login.php', trailingslashit( get_site_option( 'whl_page', 'login' ) ), $value );
	}

	/**
	 * Query vars that must not be used as a login slug.
	 *
	 * @return array
	 */
	public function forbidden_slugs() {
		$wp = new \WP();

		return array_merge( $wp->public_query_vars, $wp->private_query_vars );
	}

	/**
	 * Fix the login_url when reaching wp-admin/options.php.
	 *
	 * @param string $login_url    Login URL.
	 * @param string $redirect     Redirect target.
	 * @param bool   $force_reauth Force reauth.
	 *
	 * @return string
	 */
	public function login_url( $login_url, $redirect, $force_reauth ) {
		if ( is_404() ) {
			return '#';
		}

		if ( false === $force_reauth ) {
			return $login_url;
		}

		if ( empty( $redirect ) ) {
			return $login_url;
		}

		$redirect = explode( '?', $redirect );

		if ( admin_url( 'options.php' ) === $redirect[0] ) {
			$login_url = admin_url();
		}

		return $login_url;
	}

	/**
	 * Add a per-site "Dashboard" link on the multisite sites list.
	 *
	 * @param array  $actions  Row actions.
	 * @param int    $blog_id  Blog id.
	 * @param string $blogname Blog name.
	 *
	 * @return array
	 */
	public function manage_sites_action_links( $actions, $blog_id, $blogname ) {
		$actions['backend'] = sprintf(
			'<a href="%1$s" class="edit">%2$s</a>',
			esc_url( get_site_url( $blog_id, $this->new_login_slug() ) ),
			esc_html__( 'Dashboard', 'datametric-login-shield' )
		);

		return $actions;
	}

	/**
	 * Block wp-signup.php / wp-activate.php on single-site installs.
	 *
	 * @return void
	 */
	public function init_block_access() {
		if ( ! is_multisite()
			&& ( strpos( rawurldecode( $this->request_uri() ), 'wp-signup' ) !== false
				|| strpos( rawurldecode( $this->request_uri() ), 'wp-activate' ) !== false )
			&& false === apply_filters( 'dmls_signup_enable', false ) ) {

			wp_die( esc_html__( 'This feature is not enabled.', 'datametric-login-shield' ) );
		}
	}

	/**
	 * Send the legacy WPS Hide Login settings anchor to our own settings page.
	 *
	 * @return void
	 */
	public function legacy_settings_redirect() {
		if ( isset( $_GET['page'] ) && 'whl_settings' === sanitize_key( wp_unslash( $_GET['page'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			wp_safe_redirect( admin_url( 'admin.php?page=datametric-login-shield' ) );
			exit();
		}
	}
}
