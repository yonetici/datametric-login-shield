<?php
/**
 * Pro module: two-factor authentication with authenticator apps (TOTP).
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Modules\Totp;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use WP_User;
use WP_Error;
use Datametric\LoginShield\Container;
use Datametric\LoginShield\Contracts\ModuleInterface;
use Datametric\LoginShield\Admin\Settings;
use Datametric\LoginShield\Support\Options;
use Datametric\LoginShield\Support\Totp;

/**
 * Adds an optional second factor at login using time-based one-time passwords.
 *
 * Flow: after WordPress verifies the password (wp_login), if the user has 2FA
 * enabled we drop the just-issued auth cookie and show an interstitial that asks
 * for the 6-digit code (or a backup code). Only a valid code re-issues the auth
 * cookie. A short-lived, single-use, server-side token ties the two steps
 * together, so the password is never re-entered and cannot be replayed.
 *
 * Lockout recovery: single-use backup codes are shown at enrolment; an admin
 * can also clear a user's 2FA from the user's profile, and defining
 * DMLS_DISABLE_2FA in wp-config.php disables enforcement in an emergency.
 */
class TotpModule implements ModuleInterface {

	const META_SECRET  = '_dmlsp_totp_secret';
	const META_ENABLED = '_dmlsp_totp_enabled';
	const META_BACKUP  = '_dmlsp_totp_backup';
	const META_PENDING = '_dmlsp_totp_pending';

	const TOKEN_TRANSIENT = 'dmlsp_2fa_';
	const TOKEN_TTL       = 300; // 5 minutes.
	const MAX_ATTEMPTS    = 5;

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'pro-totp';
	}

	/**
	 * {@inheritDoc}
	 */
	public function is_pro() {
		return false;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param Container $container Shared container.
	 */
	public function register( Container $container ) {}

	/**
	 * {@inheritDoc}
	 */
	public function boot() {
		// Gate the second step at authentication time (before wp_login fires),
		// so the audit log and any login hooks only run once 2FA is verified.
		// Priority 40 runs after core auth (20) and the brute-force lockout (30).
		add_filter( 'authenticate', array( $this, 'gate_2fa' ), 40, 3 );
		add_action( 'login_form_dmlsp_2fa', array( $this, 'handle_2fa_submit' ) );

		// Application passwords bypass the interactive login (and thus 2FA), so
		// disable them for users who have a second factor enabled.
		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'block_app_passwords' ), 10, 2 );

		// Per-user enrolment on the profile screen.
		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'personal_options_update', array( $this, 'save_profile' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_profile' ) );

		// Role enforcement (soft-blocks the admin area until enrolled).
		add_action( 'admin_init', array( $this, 'enforce_enrolment' ) );

		if ( is_admin() ) {
			$this->register_settings();
		}
	}

	// Settings (role enforcement).

	/**
	 * Register the Two-Factor settings tab (one "require" toggle per role).
	 *
	 * @return void
	 */
	private function register_settings() {
		Settings::add_tab( 'two-factor', __( 'Two-Factor', 'datametric-login-shield' ), 25 );

		foreach ( $this->editable_roles() as $role => $name ) {
			Settings::add_field(
				'two-factor',
				array(
					'key'         => 'pro_2fa_require_' . $role,
					'type'        => 'checkbox',
					/* translators: %s: role display name. */
					'label'       => sprintf( __( 'Require 2FA for %s', 'datametric-login-shield' ), $name ),
					'description' => __( 'Users with this role must set up two-factor authentication.', 'datametric-login-shield' ),
					'default'     => false,
				)
			);
		}
	}

	/**
	 * Editable roles as slug => display name.
	 *
	 * @return array<string, string>
	 */
	private function editable_roles() {
		if ( ! function_exists( 'get_editable_roles' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}

		$roles = array();
		foreach ( get_editable_roles() as $slug => $data ) {
			$roles[ $slug ] = translate_user_role( $data['name'] );
		}

		return $roles;
	}

	// Enrolment state.

	/**
	 * Whether a user has an active second factor.
	 *
	 * @param WP_User|int $user User or id.
	 *
	 * @return bool
	 */
	public function user_active( $user ) {
		$user_id = ( $user instanceof WP_User ) ? $user->ID : (int) $user;

		return '1' === get_user_meta( $user_id, self::META_ENABLED, true )
			&& '' !== (string) get_user_meta( $user_id, self::META_SECRET, true );
	}

	/**
	 * Whether the given user's role requires 2FA.
	 *
	 * @param WP_User $user User.
	 *
	 * @return bool
	 */
	private function user_required( WP_User $user ) {
		foreach ( (array) $user->roles as $role ) {
			if ( Options::get( 'pro_2fa_require_' . $role, false ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Disable application passwords for users who have 2FA enabled.
	 *
	 * Application passwords authenticate REST/XML-RPC requests without the
	 * interactive login, which would bypass the second factor.
	 *
	 * @param bool    $available Whether app passwords are available.
	 * @param WP_User $user      The user.
	 *
	 * @return bool
	 */
	public function block_app_passwords( $available, $user ) {
		if ( $user instanceof WP_User && $this->user_active( $user ) ) {
			return false;
		}

		return $available;
	}

	// Login interstitial.

	/**
	 * Require a second factor once the password has been verified.
	 *
	 * Runs on the `authenticate` filter (priority 40, after core auth and the brute-force lockout check).
	 * For an interactive login it renders the code step and exits, so the auth
	 * cookie is never set and `wp_login` never fires until the code is verified
	 * in handle_2fa_submit(). Non-interactive contexts (XML-RPC, REST,
	 * application passwords, WP-CLI) cannot show a form, so they are blocked
	 * outright — this also closes the 2FA-bypass those channels would allow.
	 *
	 * @param mixed  $user     Auth result so far.
	 * @param string $username Submitted username.
	 * @param string $password Submitted password.
	 *
	 * @return mixed
	 */
	public function gate_2fa( $user, $username, $password ) {
		if ( defined( 'DMLS_DISABLE_2FA' ) && DMLS_DISABLE_2FA ) {
			return $user;
		}

		// Only act once the password already validated to a real user.
		if ( ! ( $user instanceof WP_User ) || ! $this->user_active( $user ) ) {
			return $user;
		}

		// No interactive form is possible on these channels — block instead.
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return new WP_Error( 'dmlsp_2fa_required', __( 'Two-factor authentication is required. Please sign in through the website.', 'datametric-login-shield' ) );
		}

		$remember    = ! empty( $_POST['rememberme'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- WP core login form field.
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- core login param.

		$token = $this->create_token( $user->ID, $remember, $redirect_to );

		$this->render_interstitial( $token, '' );
		exit;
	}

	/**
	 * Handle the submitted 2FA code (login action `dmlsp_2fa`).
	 *
	 * @return void
	 */
	public function handle_2fa_submit() {
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '' ) ) {
			// Direct GET to the action: nothing to show.
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		check_admin_referer( 'dmlsp_2fa' );

		$token = isset( $_POST['dmlsp_token'] ) ? sanitize_text_field( wp_unslash( $_POST['dmlsp_token'] ) ) : '';
		$code  = isset( $_POST['dmlsp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['dmlsp_code'] ) ) : '';

		$data = $this->get_token( $token );
		if ( ! $data ) {
			$this->render_interstitial( '', __( 'Your login session expired. Please sign in again.', 'datametric-login-shield' ), true );
			exit;
		}

		// Too many wrong tries: burn the token.
		if ( $data['attempts'] >= self::MAX_ATTEMPTS ) {
			$this->delete_token( $token );
			$this->render_interstitial( '', __( 'Too many attempts. Please sign in again.', 'datametric-login-shield' ), true );
			exit;
		}

		$secret = (string) get_user_meta( $data['user_id'], self::META_SECRET, true );
		$ok     = Totp::verify( $secret, $code ) || $this->consume_backup_code( $data['user_id'], $code );

		if ( ! $ok ) {
			$data['attempts']++;
			$this->put_token( $token, $data );
			// Fire the standard failed-login hook so the audit log records it and
			// the brute-force module counts it (throttling 2FA-code guessing).
			$failed_user = get_userdata( $data['user_id'] );
			do_action(
				'wp_login_failed', // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing the WordPress core hook so the audit log and brute-force module see the failed 2FA.
				$failed_user ? $failed_user->user_login : '',
				new WP_Error( 'dmlsp_2fa', __( 'Invalid two-factor code.', 'datametric-login-shield' ) )
			);
			$this->render_interstitial( $token, __( 'Invalid code. Please try again.', 'datametric-login-shield' ) );
			exit;
		}

		// Success: complete the login.
		$this->delete_token( $token );
		wp_set_auth_cookie( $data['user_id'], (bool) $data['remember'] );
		$user = get_userdata( $data['user_id'] );
		if ( $user ) {
			wp_set_current_user( $user->ID );
			/**
			 * Fire the standard login hook now that authentication is fully
			 * complete. This is the only time wp_login runs for a 2FA user, so
			 * the audit log records exactly one login_success.
			 */
			do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- re-firing WordPress core hook after 2FA completes.
		}

		$redirect = ! empty( $data['redirect_to'] ) ? $data['redirect_to'] : admin_url();
		wp_safe_redirect( $redirect );
		exit;
	}

	// Token store (single-use, server-side).

	/**
	 * Create a login token.
	 *
	 * @param int    $user_id     User id.
	 * @param bool   $remember    Remember-me.
	 * @param string $redirect_to Post-login redirect.
	 *
	 * @return string
	 */
	private function create_token( $user_id, $remember, $redirect_to ) {
		$token = wp_generate_password( 32, false );
		$this->put_token(
			$token,
			array(
				'user_id'     => (int) $user_id,
				'remember'    => (bool) $remember,
				'redirect_to' => (string) $redirect_to,
				'attempts'    => 0,
			)
		);

		return $token;
	}

	/**
	 * Persist a token's data.
	 *
	 * @param string $token Token.
	 * @param array  $data  Data.
	 *
	 * @return void
	 */
	private function put_token( $token, array $data ) {
		set_transient( self::TOKEN_TRANSIENT . hash( 'sha256', $token ), $data, self::TOKEN_TTL );
	}

	/**
	 * Fetch a token's data.
	 *
	 * @param string $token Token.
	 *
	 * @return array|false
	 */
	private function get_token( $token ) {
		if ( '' === $token ) {
			return false;
		}
		$data = get_transient( self::TOKEN_TRANSIENT . hash( 'sha256', $token ) );

		return is_array( $data ) ? $data : false;
	}

	/**
	 * Delete a token.
	 *
	 * @param string $token Token.
	 *
	 * @return void
	 */
	private function delete_token( $token ) {
		delete_transient( self::TOKEN_TRANSIENT . hash( 'sha256', $token ) );
	}

	// Backup codes.

	/**
	 * Generate a fresh set of backup codes, store their hashes, return plaintext.
	 *
	 * @param int $user_id User id.
	 *
	 * @return string[] Plaintext codes (shown once).
	 */
	private function generate_backup_codes( $user_id ) {
		$plain  = array();
		$hashed = array();
		for ( $i = 0; $i < 8; $i++ ) {
			$code    = strtolower( wp_generate_password( 10, false ) );
			$plain[] = $code;
			$hashed[] = wp_hash_password( $code );
		}
		update_user_meta( $user_id, self::META_BACKUP, $hashed );

		return $plain;
	}

	/**
	 * Consume a backup code if it matches; single-use.
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted code.
	 *
	 * @return bool
	 */
	private function consume_backup_code( $user_id, $code ) {
		$code   = strtolower( preg_replace( '/\s+/', '', (string) $code ) );
		$hashes = get_user_meta( $user_id, self::META_BACKUP, true );
		if ( ! is_array( $hashes ) || '' === $code ) {
			return false;
		}

		foreach ( $hashes as $index => $hash ) {
			if ( wp_check_password( $code, $hash ) ) {
				unset( $hashes[ $index ] );
				update_user_meta( $user_id, self::META_BACKUP, array_values( $hashes ) );

				return true;
			}
		}

		return false;
	}

	// Enforcement.

	/**
	 * Redirect required-but-unenrolled users to their profile to set up 2FA.
	 *
	 * @return void
	 */
	public function enforce_enrolment() {
		if ( defined( 'DMLS_DISABLE_2FA' ) && DMLS_DISABLE_2FA ) {
			return;
		}

		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}

		$user = wp_get_current_user();
		if ( ! $this->user_required( $user ) || $this->user_active( $user ) ) {
			return;
		}

		global $pagenow;
		// Allow the profile screen (to enrol) and logout.
		if ( in_array( $pagenow, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		if ( isset( $_GET['action'] ) && 'logout' === sanitize_key( wp_unslash( $_GET['action'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing.
			return;
		}

		add_action(
			'admin_notices',
			function () {
				echo '<div class="notice notice-error"><p>' . esc_html__( 'Your role requires two-factor authentication. Please set it up below to continue.', 'datametric-login-shield' ) . '</p></div>';
			}
		);

		wp_safe_redirect( admin_url( 'profile.php#dmlsp-2fa' ) );
		exit;
	}

	// Profile UI.

	/**
	 * Render the 2FA section on the user profile screen.
	 *
	 * @param WP_User $user Profile user.
	 *
	 * @return void
	 */
	public function render_profile_section( $user ) {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}

		$active = $this->user_active( $user );
		wp_nonce_field( 'dmlsp_profile_2fa_' . $user->ID, 'dmlsp_profile_nonce' );
		echo '<h2 id="dmlsp-2fa">' . esc_html__( 'Two-Factor Authentication', 'datametric-login-shield' ) . '</h2>';

		// Show freshly generated backup codes once (right after enabling).
		$fresh_codes = get_transient( 'dmlsp_backup_show_' . $user->ID );
		if ( is_array( $fresh_codes ) && ! empty( $fresh_codes ) ) {
			delete_transient( 'dmlsp_backup_show_' . $user->ID );
			echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'Your backup codes (each works once) — save them now:', 'datametric-login-shield' ) . '</strong></p><p><code>' . esc_html( implode( '  ', $fresh_codes ) ) . '</code></p></div>';
		}
		echo '<table class="form-table" role="presentation"><tr><th scope="row">' . esc_html__( 'Authenticator app', 'datametric-login-shield' ) . '</th><td>';

		if ( $active ) {
			echo '<p><strong style="color:#12B5A5">' . esc_html__( 'Enabled.', 'datametric-login-shield' ) . '</strong></p>';
			echo '<label><input type="checkbox" name="dmlsp_2fa_disable" value="1"> ' . esc_html__( 'Turn off two-factor authentication for this account.', 'datametric-login-shield' ) . '</label>';
		} else {
			// Ensure a pending secret exists to display.
			$secret = (string) get_user_meta( $user->ID, self::META_PENDING, true );
			if ( '' === $secret ) {
				$secret = Totp::generate_secret();
				update_user_meta( $user->ID, self::META_PENDING, $secret );
			}
			$issuer  = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
			$uri     = Totp::provisioning_uri( $secret, $user->user_login, $issuer );

			echo '<p>' . esc_html__( 'Add this account to Google Authenticator, Authy or 1Password, then enter the 6-digit code to enable.', 'datametric-login-shield' ) . '</p>';
			echo '<p>' . esc_html__( 'Secret key (manual entry):', 'datametric-login-shield' ) . ' <code>' . esc_html( $secret ) . '</code></p>';
			echo '<p><a href="' . esc_attr( $uri ) . '">' . esc_html__( 'Open in your authenticator app', 'datametric-login-shield' ) . '</a></p>';
			echo '<p><label>' . esc_html__( 'Verification code', 'datametric-login-shield' ) . ' <input type="text" name="dmlsp_2fa_confirm" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" maxlength="6"></label></p>';
		}

		echo '</td></tr></table>';
	}

	/**
	 * Persist profile 2FA changes (enable via confirm code, or disable).
	 *
	 * @param int $user_id Profile user id.
	 *
	 * @return void
	 */
	public function save_profile( $user_id ) {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		if ( ! isset( $_POST['dmlsp_profile_nonce'] )
			|| ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['dmlsp_profile_nonce'] ) ), 'dmlsp_profile_2fa_' . $user_id ) ) {
			return;
		}

		// Disable.
		if ( ! empty( $_POST['dmlsp_2fa_disable'] ) ) {
			delete_user_meta( $user_id, self::META_SECRET );
			delete_user_meta( $user_id, self::META_ENABLED );
			delete_user_meta( $user_id, self::META_BACKUP );
			return;
		}

		// Enable: confirm a code against the pending secret.
		$confirm = isset( $_POST['dmlsp_2fa_confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['dmlsp_2fa_confirm'] ) ) : '';
		if ( '' === $confirm ) {
			return;
		}

		$pending = (string) get_user_meta( $user_id, self::META_PENDING, true );
		if ( '' !== $pending && Totp::verify( $pending, $confirm ) ) {
			update_user_meta( $user_id, self::META_SECRET, $pending );
			update_user_meta( $user_id, self::META_ENABLED, '1' );
			delete_user_meta( $user_id, self::META_PENDING );
			$codes = $this->generate_backup_codes( $user_id );
			set_transient( 'dmlsp_backup_show_' . $user_id, $codes, 120 );

			// Revoke any application passwords and invalidate other sessions so
			// nothing keeps 2FA-free access to this account.
			if ( class_exists( '\WP_Application_Passwords' ) ) {
				\WP_Application_Passwords::delete_all_application_passwords( $user_id );
			}
			if ( get_current_user_id() === (int) $user_id ) {
				wp_destroy_other_sessions();
			} else {
				\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
			}

			add_action(
				'user_profile_update_errors',
				function ( $errors ) {
					$errors->add( 'dmlsp_2fa', __( 'Two-factor authentication enabled. Save your backup codes now.', 'datametric-login-shield' ), 'message' );
				}
			);
		}
	}

	// Rendering.

	/**
	 * Render the login interstitial (code entry) page and stop.
	 *
	 * @param string $token   Login token (empty when session is dead).
	 * @param string $message Optional error/notice message.
	 * @param bool   $dead    When true, offer a link back to login instead of the form.
	 *
	 * @return void
	 */
	private function render_interstitial( $token, $message = '', $dead = false ) {
		$action = add_query_arg( 'action', 'dmlsp_2fa', site_url( 'wp-login.php', 'login_post' ) );
		$title  = __( 'Two-Factor Authentication', 'datametric-login-shield' );

		// login_header()/login_footer() exist only when wp-login.php is loaded.
		// On front-end login forms (e.g. WooCommerce) they are undefined, so we
		// fall back to a self-contained page instead of fataling.
		$has_login_ui = function_exists( 'login_header' ) && function_exists( 'login_footer' );

		if ( $has_login_ui ) {
			login_header( $title, '' );
		} else {
			$this->minimal_header( $title );
		}

		if ( '' !== $message ) {
			echo '<div id="login_error">' . esc_html( $message ) . '</div>';
		}

		if ( $dead ) {
			echo '<p><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Back to sign in', 'datametric-login-shield' ) . '</a></p>';
		} else {
			echo '<form name="dmlsp_2fa" method="post" action="' . esc_url( $action ) . '">';
			echo '<p><label for="dmlsp_code">' . esc_html__( 'Authentication code', 'datametric-login-shield' ) . '<br />';
			echo '<input type="text" name="dmlsp_code" id="dmlsp_code" class="input" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" autofocus /></label></p>';
			echo '<input type="hidden" name="dmlsp_token" value="' . esc_attr( $token ) . '" />';
			wp_nonce_field( 'dmlsp_2fa' );
			echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__( 'Verify', 'datametric-login-shield' ) . '" /></p>';
			echo '<p class="description">' . esc_html__( 'Lost your device? Enter one of your backup codes instead.', 'datametric-login-shield' ) . '</p>';
			echo '</form>';
		}

		if ( $has_login_ui ) {
			login_footer( $dead ? '' : 'dmlsp_code' );
		} else {
			$this->minimal_footer();
		}
	}

	/**
	 * Minimal self-contained page header (used when wp-login.php UI is absent).
	 *
	 * @param string $title Page title.
	 *
	 * @return void
	 */
	private function minimal_header( $title ) {
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=' . get_option( 'blog_charset', 'UTF-8' ) );
		}
		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="<?php bloginfo( 'charset' ); ?>" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title><?php echo esc_html( $title ); ?></title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f0f0f1;margin:0;padding:10vh 16px}
#dmlsp-box{max-width:320px;margin:0 auto;background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:24px}
#dmlsp-box h1{font-size:18px;color:#1e2a4a;margin:0 0 16px}
#dmlsp-box input[type=text]{width:100%;padding:9px;box-sizing:border-box;font-size:20px;letter-spacing:3px;text-align:center}
#dmlsp-box .button-primary{margin-top:14px;padding:9px 18px;background:#1e2a4a;color:#fff;border:0;border-radius:6px;cursor:pointer;font-size:14px}
#login_error{color:#b32d2e;margin-bottom:12px}
.description{color:#666;font-size:12px;margin-top:14px}
label{color:#1e2a4a;font-size:13px}
</style>
</head>
<body><div id="dmlsp-box"><h1><?php echo esc_html( $title ); ?></h1>
		<?php
	}

	/**
	 * Minimal self-contained page footer.
	 *
	 * @return void
	 */
	private function minimal_footer() {
		echo '</div></body></html>';
	}
}
