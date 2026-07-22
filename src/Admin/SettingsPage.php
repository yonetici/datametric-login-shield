<?php
/**
 * Modern admin settings screen.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use Datametric\LoginShield\Plugin;
use Datametric\LoginShield\Support\Options;

/**
 * Registers the top-level "Login Shield" menu and renders a tabbed settings UI.
 *
 * Phase-2 / Pro modules add their own tabs through the `dls_settings_tabs`
 * filter and never need to touch this class.
 */
class SettingsPage {

	const MENU_SLUG    = 'datametric-login-shield';
	const CAPABILITY   = 'manage_options';
	const NONCE_ACTION = 'dls_save_settings';
	const NONCE_FIELD  = 'dls_nonce';

	/**
	 * Transient-style notice to show after a redirect.
	 *
	 * @var array{type:string,message:string}|null
	 */
	private $notice;

	/**
	 * Add hooks.
	 *
	 * @return void
	 */
	public function boot() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'maybe_handle_post' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	/**
	 * Register the top-level menu.
	 *
	 * @return void
	 */
	public function register_menu() {
		add_menu_page(
			__( 'Login Shield', 'datametric-login-shield' ),
			__( 'Login Shield', 'datametric-login-shield' ),
			self::CAPABILITY,
			self::MENU_SLUG,
			array( $this, 'render_page' ),
			$this->menu_icon(),
			'80.7'
		);
	}

	/**
	 * Enqueue admin styles only on our page.
	 *
	 * @param string $hook Current admin page hook.
	 *
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( 'toplevel_page_' . self::MENU_SLUG !== $hook ) {
			return;
		}

		wp_enqueue_style(
			'dls-admin',
			DLS_URL . 'assets/css/admin.css',
			array(),
			DLS_VERSION
		);

		wp_enqueue_script(
			'dls-admin',
			DLS_URL . 'assets/js/admin.js',
			array(),
			DLS_VERSION,
			true
		);

		wp_localize_script(
			'dls-admin',
			'dlsAdmin',
			array(
				'copied' => __( 'Copied!', 'datametric-login-shield' ),
			)
		);
	}

	/**
	 * Define the settings tabs. Pro modules extend this via the filter.
	 *
	 * @return array<string, array{label:string, render:callable}>
	 */
	public function tabs() {
		$start = array(
			'dashboard' => array(
				'label'  => __( 'Dashboard', 'datametric-login-shield' ),
				'render' => array( $this, 'render_dashboard' ),
			),
			'login-url' => array(
				'label'  => __( 'Login URL', 'datametric-login-shield' ),
				'render' => array( $this, 'render_login_url' ),
			),
		);

		// Tabs registered by modules (Protection, Audit Log, …).
		$registry = array();
		foreach ( Settings::tabs() as $slug => $tab ) {
			$render = $tab['render'];
			if ( ! is_callable( $render ) ) {
				$render = function () use ( $slug ) {
					$this->render_registry_form( $slug );
				};
			}
			$registry[ $slug ] = array(
				'label'  => $tab['label'],
				'render' => $render,
			);
		}

		$end = array(
			'advanced' => array(
				'label'  => __( 'Advanced', 'datametric-login-shield' ),
				'render' => array( $this, 'render_advanced' ),
			),
		);

		$tabs = array_merge( $start, $registry, $end );

		/**
		 * Filter the Login Shield settings tabs.
		 *
		 * @param array $tabs Tab definitions keyed by slug.
		 */
		return apply_filters( 'dls_settings_tabs', $tabs );
	}

	/**
	 * Render a standard form for a registry tab's fields.
	 *
	 * @param string $tab Tab slug.
	 *
	 * @return void
	 */
	private function render_registry_form( $tab ) {
		echo '<form method="post" class="dls-form">';
		wp_nonce_field( self::NONCE_ACTION, self::NONCE_FIELD );
		echo '<input type="hidden" name="dls_action" value="save_fields" />';
		echo '<input type="hidden" name="dls_tab" value="' . esc_attr( $tab ) . '" />';
		Settings::render_fields( $tab );
		submit_button();
		echo '</form>';
	}

	/**
	 * Currently active tab slug.
	 *
	 * @return string
	 */
	private function current_tab() {
		$tabs    = $this->tabs();
		$default = 'dashboard';

		if ( isset( $_GET['tab'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only navigation.
			$tab = sanitize_key( wp_unslash( $_GET['tab'] ) );
			if ( isset( $tabs[ $tab ] ) ) {
				return $tab;
			}
		}

		return $default;
	}

	/**
	 * Handle form submissions for our page.
	 *
	 * @return void
	 */
	public function maybe_handle_post() {
		if ( ! isset( $_POST['dls_action'] ) ) {
			return;
		}

		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'datametric-login-shield' ) );
		}

		check_admin_referer( self::NONCE_ACTION, self::NONCE_FIELD );

		$action = sanitize_key( wp_unslash( $_POST['dls_action'] ) );

		switch ( $action ) {
			case 'save_login_url':
				$this->handle_save_login_url();
				break;

			case 'save_advanced':
				$this->handle_save_advanced();
				break;

			case 'save_fields':
				$this->handle_save_fields();
				break;

			case 'email_login_url':
				$this->handle_email_login_url();
				break;
		}
	}

	/**
	 * Save login slug + redirect slug.
	 *
	 * @return void
	 */
	private function handle_save_login_url() {
		// Nonce + capability are verified centrally in maybe_handle_post().
		$login_slug    = isset( $_POST['login_slug'] ) ? sanitize_title_with_dashes( wp_unslash( $_POST['login_slug'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$redirect_slug = isset( $_POST['redirect_slug'] ) ? sanitize_title_with_dashes( wp_unslash( $_POST['redirect_slug'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

		$error = $this->validate_login_slug( $login_slug );

		if ( $error ) {
			$this->redirect_with_notice( 'error', $error, 'login-url' );
		}

		if ( '' === $redirect_slug ) {
			$redirect_slug = Options::DEFAULT_REDIRECT_SLUG;
		}

		Options::update(
			array(
				'login_slug'    => $login_slug,
				'redirect_slug' => $redirect_slug,
			)
		);

		flush_rewrite_rules( false );

		$this->redirect_with_notice(
			'success',
			__( 'Settings saved. Your new login URL is shown below — save it now so you do not lock yourself out.', 'datametric-login-shield' ),
			'login-url'
		);
	}

	/**
	 * Validate a login slug; return an error message or empty string.
	 *
	 * @param string $slug Sanitized slug.
	 *
	 * @return string
	 */
	private function validate_login_slug( $slug ) {
		if ( '' === $slug ) {
			return __( 'The login URL cannot be empty.', 'datametric-login-shield' );
		}

		if ( false !== strpos( $slug, 'wp-login' ) ) {
			return __( 'The login URL cannot contain "wp-login".', 'datametric-login-shield' );
		}

		$reserved = array( 'wp-admin', 'admin', 'wp-login', 'wp-content', 'wp-includes', 'index', 'wp-signup', 'wp-activate' );
		if ( in_array( $slug, $reserved, true ) ) {
			return sprintf(
				/* translators: %s: the reserved slug the user tried to use. */
				__( '"%s" is a reserved word and cannot be used as a login URL.', 'datametric-login-shield' ),
				$slug
			);
		}

		$hide_login = $this->hide_login();
		if ( $hide_login && in_array( $slug, (array) $hide_login->forbidden_slugs(), true ) ) {
			return __( 'This word is reserved by WordPress and cannot be used as a login URL.', 'datametric-login-shield' );
		}

		// Warn if the slug collides with an existing published page.
		if ( get_option( 'permalink_structure' ) ) {
			$existing = get_page_by_path( $slug );
			if ( $existing instanceof \WP_Post ) {
				return __( 'A page already exists at this URL. Choose a different login URL.', 'datametric-login-shield' );
			}
		}

		return '';
	}

	/**
	 * Save fields registered under a module tab via the Settings registry.
	 *
	 * @return void
	 */
	private function handle_save_fields() {
		// Nonce + capability verified in maybe_handle_post().
		$tab = isset( $_POST['dls_tab'] ) ? sanitize_key( wp_unslash( $_POST['dls_tab'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

		$fields = Settings::fields_for( $tab );

		if ( empty( $fields ) ) {
			$this->redirect_with_notice( 'error', __( 'Nothing to save.', 'datametric-login-shield' ), $tab ? $tab : 'dashboard' );
		}

		$values = array();
		foreach ( $fields as $field ) {
			$key = $field['key'];
			$raw = array_key_exists( $key, $_POST ) ? wp_unslash( $_POST[ $key ] ) : null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Missing -- sanitized per-field below; nonce verified in maybe_handle_post().
			$values[ $key ] = Settings::sanitize_value( $field, $raw );
		}

		Options::update( $values );

		$this->redirect_with_notice(
			'success',
			__( 'Settings saved.', 'datametric-login-shield' ),
			$tab
		);
	}

	/**
	 * Save advanced settings (uninstall behaviour).
	 *
	 * @return void
	 */
	private function handle_save_advanced() {
		Options::update(
			array(
				// Nonce + capability verified in maybe_handle_post().
				'uninstall_purge' => ! empty( $_POST['uninstall_purge'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);

		$this->redirect_with_notice(
			'success',
			__( 'Advanced settings saved.', 'datametric-login-shield' ),
			'advanced'
		);
	}

	/**
	 * Email the current login URL to the logged-in admin.
	 *
	 * @return void
	 */
	private function handle_email_login_url() {
		$user  = wp_get_current_user();
		$email = $user->user_email;

		if ( ! is_email( $email ) ) {
			$this->redirect_with_notice( 'error', __( 'Your account has no valid email address.', 'datametric-login-shield' ), 'dashboard' );
		}

		$url     = $this->login_url();
		$subject = sprintf(
			/* translators: %s: site name. */
			__( '[%s] Your login URL', 'datametric-login-shield' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
		);
		$body = sprintf(
			/* translators: %s: the login URL. */
			__( "Keep this safe. Your WordPress login URL is:\n\n%s\n\n— Datametric Login Shield", 'datametric-login-shield' ),
			$url
		);

		$sent = wp_mail( $email, $subject, $body );

		if ( $sent ) {
			$this->redirect_with_notice(
				'success',
				/* translators: %s: admin email address. */
				sprintf( __( 'We emailed your login URL to %s.', 'datametric-login-shield' ), $email ),
				'dashboard'
			);
		} else {
			$this->redirect_with_notice( 'error', __( 'We could not send the email. Check your site email configuration.', 'datametric-login-shield' ), 'dashboard' );
		}
	}

	/**
	 * Store a notice and redirect back to the given tab (PRG pattern).
	 *
	 * @param string $type    "success" or "error".
	 * @param string $message Message text.
	 * @param string $tab     Tab slug to return to.
	 *
	 * @return void
	 */
	private function redirect_with_notice( $type, $message, $tab ) {
		set_transient( 'dls_notice_' . get_current_user_id(), array( 'type' => $type, 'message' => $message ), 60 );

		wp_safe_redirect( $this->tab_url( $tab ) );
		exit();
	}

	/**
	 * Build the admin URL for a given tab.
	 *
	 * @param string $tab Tab slug.
	 *
	 * @return string
	 */
	private function tab_url( $tab ) {
		return add_query_arg(
			array(
				'page' => self::MENU_SLUG,
				'tab'  => $tab,
			),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * Render the whole page (header, tabs, active tab body).
	 *
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}

		$this->notice = get_transient( 'dls_notice_' . get_current_user_id() );
		if ( $this->notice ) {
			delete_transient( 'dls_notice_' . get_current_user_id() );
		}

		$tabs    = $this->tabs();
		$current = $this->current_tab();
		?>
		<div class="wrap dls-wrap">
			<div class="dls-header">
				<img class="dls-logo" src="<?php echo esc_url( DLS_URL . 'assets/img/logo.svg' ); ?>" alt="" width="40" height="40" />
				<div>
					<h1 class="dls-title"><?php esc_html_e( 'Datametric Login Shield', 'datametric-login-shield' ); ?></h1>
					<p class="dls-subtitle"><?php esc_html_e( 'Hide your login and lock down access.', 'datametric-login-shield' ); ?></p>
				</div>
			</div>

			<?php if ( is_array( $this->notice ) && ! empty( $this->notice['message'] ) ) : ?>
				<div class="notice notice-<?php echo 'error' === $this->notice['type'] ? 'error' : 'success'; ?> dls-notice">
					<p><?php echo esc_html( $this->notice['message'] ); ?></p>
				</div>
			<?php endif; ?>

			<nav class="nav-tab-wrapper dls-tabs">
				<?php foreach ( $tabs as $slug => $tab ) : ?>
					<a href="<?php echo esc_url( $this->tab_url( $slug ) ); ?>"
						class="nav-tab <?php echo $slug === $current ? 'nav-tab-active' : ''; ?>">
						<?php echo esc_html( $tab['label'] ); ?>
					</a>
				<?php endforeach; ?>
			</nav>

			<div class="dls-body">
				<?php
				if ( isset( $tabs[ $current ]['render'] ) && is_callable( $tabs[ $current ]['render'] ) ) {
					call_user_func( $tabs[ $current ]['render'] );
				}
				?>
			</div>

			<p class="dls-footer">
				<?php
				printf(
					/* translators: %s: plugin version. */
					esc_html__( 'Datametric Login Shield %s — the login-security layer.', 'datametric-login-shield' ),
					esc_html( 'v' . DLS_VERSION )
				);
				?>
			</p>
		</div>
		<?php
	}

	/**
	 * Dashboard tab.
	 *
	 * @return void
	 */
	public function render_dashboard() {
		$url  = $this->login_url();
		$slug = Options::login_slug();
		?>
		<div class="dls-cards">
			<div class="dls-card dls-card--primary">
				<span class="dls-card__label"><?php esc_html_e( 'Your login URL', 'datametric-login-shield' ); ?></span>
				<div class="dls-url-row">
					<input type="text" class="dls-url-field" readonly value="<?php echo esc_attr( $url ); ?>"
						onclick="this.select();" />
					<button type="button" class="button dls-copy" data-clipboard="<?php echo esc_attr( $url ); ?>">
						<?php esc_html_e( 'Copy', 'datametric-login-shield' ); ?>
					</button>
				</div>
				<form method="post" class="dls-inline-form">
					<?php wp_nonce_field( self::NONCE_ACTION, self::NONCE_FIELD ); ?>
					<input type="hidden" name="dls_action" value="email_login_url" />
					<button type="submit" class="button button-secondary">
						<?php esc_html_e( 'Email this URL to me', 'datametric-login-shield' ); ?>
					</button>
				</form>
				<p class="dls-hint"><?php esc_html_e( 'Bookmark this URL. wp-login.php and wp-admin are now blocked for logged-out visitors.', 'datametric-login-shield' ); ?></p>
			</div>

			<div class="dls-card">
				<span class="dls-card__label"><?php esc_html_e( 'Status', 'datametric-login-shield' ); ?></span>
				<?php
				$bf_on    = (bool) Options::get( 'bruteforce_enabled', true );
				$audit_on = (bool) Options::get( 'audit_enabled', true );
				?>
				<ul class="dls-status">
					<li class="is-on"><?php esc_html_e( 'Login URL hidden', 'datametric-login-shield' ); ?> <code><?php echo esc_html( '/' . $slug ); ?></code></li>
					<li class="is-on"><?php esc_html_e( 'wp-admin protected for logged-out users', 'datametric-login-shield' ); ?></li>
					<li class="<?php echo $bf_on ? 'is-on' : ''; ?>"><?php esc_html_e( 'Brute-force protection', 'datametric-login-shield' ); ?></li>
					<li class="<?php echo $audit_on ? 'is-on' : ''; ?>"><?php esc_html_e( 'Login activity logging', 'datametric-login-shield' ); ?></li>
				</ul>
				<a class="button button-primary" href="<?php echo esc_url( $this->tab_url( 'login-url' ) ); ?>">
					<?php esc_html_e( 'Change login URL', 'datametric-login-shield' ); ?>
				</a>
			</div>
		</div>

		<?php $this->render_roadmap(); ?>
		<?php
	}

	/**
	 * Login URL tab (the core settings form).
	 *
	 * @return void
	 */
	public function render_login_url() {
		$home  = trailingslashit( home_url() );
		$perma = (bool) get_option( 'permalink_structure' );
		$slug  = Options::login_slug();
		$redir = Options::redirect_slug();
		?>
		<form method="post" class="dls-form">
			<?php wp_nonce_field( self::NONCE_ACTION, self::NONCE_FIELD ); ?>
			<input type="hidden" name="dls_action" value="save_login_url" />

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="dls_login_slug"><?php esc_html_e( 'Login URL', 'datametric-login-shield' ); ?></label></th>
					<td>
						<code><?php echo esc_html( $home . ( $perma ? '' : '?' ) ); ?></code>
						<input name="login_slug" id="dls_login_slug" type="text" value="<?php echo esc_attr( $slug ); ?>" class="regular-text" />
						<p class="description"><?php esc_html_e( 'The address people will use to reach the login form. Avoid "login" — pick something only you know.', 'datametric-login-shield' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="dls_redirect_slug"><?php esc_html_e( 'Redirect URL', 'datametric-login-shield' ); ?></label></th>
					<td>
						<code><?php echo esc_html( $home . ( $perma ? '' : '?' ) ); ?></code>
						<input name="redirect_slug" id="dls_redirect_slug" type="text" value="<?php echo esc_attr( $redir ); ?>" class="regular-text" />
						<p class="description"><?php esc_html_e( 'Where logged-out visitors are sent when they try to reach wp-login.php or wp-admin. Default: 404.', 'datametric-login-shield' ); ?></p>
					</td>
				</tr>
			</table>

			<p class="dls-warning">
				<strong><?php esc_html_e( 'Heads up:', 'datametric-login-shield' ); ?></strong>
				<?php esc_html_e( 'After saving, you will only be able to log in at the new URL. Make sure you copy or email it to yourself.', 'datametric-login-shield' ); ?>
			</p>

			<?php submit_button( __( 'Save login URL', 'datametric-login-shield' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Advanced tab.
	 *
	 * @return void
	 */
	public function render_advanced() {
		$purge = (bool) Options::get( 'uninstall_purge', false );
		?>
		<form method="post" class="dls-form">
			<?php wp_nonce_field( self::NONCE_ACTION, self::NONCE_FIELD ); ?>
			<input type="hidden" name="dls_action" value="save_advanced" />

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'On uninstall', 'datametric-login-shield' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="uninstall_purge" value="1" <?php checked( $purge ); ?> />
							<?php esc_html_e( 'Delete all Datametric Login Shield data when the plugin is uninstalled.', 'datametric-login-shield' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'When enabled, removing the plugin also removes its settings. Leave off to keep your configuration.', 'datametric-login-shield' ); ?></p>
					</td>
				</tr>
			</table>

			<?php submit_button( __( 'Save advanced settings', 'datametric-login-shield' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Show the "coming soon" roadmap of Pro/Phase-2 modules (review-friendly,
	 * shown only inside our own page, no nagging elsewhere).
	 *
	 * @return void
	 */
	private function render_roadmap() {
		$items = array(
			__( 'Two-factor authentication (email code)', 'datametric-login-shield' ),
			__( 'Two-factor with authenticator apps (Pro)', 'datametric-login-shield' ),
			__( 'IP allow / deny lists (Pro)', 'datametric-login-shield' ),
			__( 'CAPTCHA on login (Pro)', 'datametric-login-shield' ),
			__( 'Custom login page branding (Pro)', 'datametric-login-shield' ),
		);
		?>
		<div class="dls-card dls-roadmap">
			<span class="dls-card__label"><?php esc_html_e( 'Coming next', 'datametric-login-shield' ); ?></span>
			<ul class="dls-roadmap__list">
				<?php foreach ( $items as $item ) : ?>
					<li><?php echo esc_html( $item ); ?></li>
				<?php endforeach; ?>
			</ul>
		</div>
		<?php
	}

	/**
	 * Resolve the current login URL, preferring the core module.
	 *
	 * @return string
	 */
	private function login_url() {
		$hide_login = $this->hide_login();
		if ( $hide_login ) {
			return $hide_login->new_login_url();
		}

		// Fallback (should not normally happen).
		$home = trailingslashit( home_url() );
		$slug = Options::login_slug();

		return get_option( 'permalink_structure' ) ? $home . $slug : $home . '?' . $slug;
	}

	/**
	 * Get the HideLogin core module from the container.
	 *
	 * @return \Datametric\LoginShield\Modules\HideLogin\HideLoginModule|null
	 */
	private function hide_login() {
		$container = Plugin::get_instance()->container();

		return $container && $container->has( 'hide_login' ) ? $container->get( 'hide_login' ) : null;
	}

	/**
	 * Base64-encoded SVG for the admin menu icon (monochrome; WP recolours it).
	 *
	 * @return string
	 */
	private function menu_icon() {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="black"><path d="M12 1.5 3.5 5v6.2c0 5.1 3.6 9.4 8.5 10.8 4.9-1.4 8.5-5.7 8.5-10.8V5L12 1.5Zm0 5.4a2.6 2.6 0 0 1 1.2 4.9v2.3a1.2 1.2 0 1 1-2.4 0v-2.3A2.6 2.6 0 0 1 12 6.9Z"/></svg>';

		return 'data:image/svg+xml;base64,' . base64_encode( $svg );
	}
}
