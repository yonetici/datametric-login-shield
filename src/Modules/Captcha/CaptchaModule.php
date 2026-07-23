<?php
/**
 * Pro module: CAPTCHA on the login form.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Modules\Captcha;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use WP_Error;
use Datametric\LoginShield\Container;
use Datametric\LoginShield\Contracts\ModuleInterface;
use Datametric\LoginShield\Admin\Settings;
use Datametric\LoginShield\Support\Options;
use Datametric\LoginShield\Support\Ip;

/**
 * Adds a CAPTCHA challenge (Google reCAPTCHA v2/v3, hCaptcha or Cloudflare
 * Turnstile) to the login form and verifies it server-side.
 *
 * Privacy: when enabled, the chosen provider's script runs on the login page
 * and the challenge response is sent to that provider for verification. This is
 * documented in the Pro readme; keep it disabled to make no third-party calls.
 */
class CaptchaModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'pro-captcha';
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
		if ( is_admin() ) {
			$this->register_settings();
		}

		// Emergency escape hatch: if the provider script fails in the browser
		// (region block, CDN outage) admins can define this to log in via FTP.
		if ( defined( 'DMLS_DISABLE_CAPTCHA' ) && DMLS_DISABLE_CAPTCHA ) {
			return;
		}

		if ( ! $this->is_configured() ) {
			return;
		}

		add_action( 'login_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'login_form', array( $this, 'render_widget' ) );
		add_filter( 'authenticate', array( $this, 'verify' ), 21, 3 );
	}

	/**
	 * Provider definitions.
	 *
	 * @return array<string, array>
	 */
	private function providers() {
		return array(
			'recaptcha_v2' => array(
				'script' => 'https://www.google.com/recaptcha/api.js',
				'verify' => 'https://www.google.com/recaptcha/api/siteverify',
				'field'  => 'g-recaptcha-response',
				'markup' => '<div class="g-recaptcha" data-sitekey="%s"></div>',
			),
			'recaptcha_v3' => array(
				'script' => 'https://www.google.com/recaptcha/api.js?render=%s',
				'verify' => 'https://www.google.com/recaptcha/api/siteverify',
				'field'  => 'g-recaptcha-response',
				'markup' => '',
			),
			'hcaptcha'     => array(
				'script' => 'https://js.hcaptcha.com/1/api.js',
				'verify' => 'https://hcaptcha.com/siteverify',
				'field'  => 'h-captcha-response',
				'markup' => '<div class="h-captcha" data-sitekey="%s"></div>',
			),
			'turnstile'    => array(
				'script' => 'https://challenges.cloudflare.com/turnstile/v0/api.js',
				'verify' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
				'field'  => 'cf-turnstile-response',
				'markup' => '<div class="cf-turnstile" data-sitekey="%s"></div>',
			),
		);
	}

	/**
	 * Register the CAPTCHA settings tab.
	 *
	 * @return void
	 */
	private function register_settings() {
		Settings::add_tab( 'captcha', __( 'CAPTCHA', 'datametric-login-shield' ), 27 );

		Settings::add_field(
			'captcha',
			array(
				'key'     => 'pro_captcha_provider',
				'type'    => 'select',
				'label'   => __( 'Provider', 'datametric-login-shield' ),
				'default' => '',
				'options' => array(
					''             => __( 'Disabled', 'datametric-login-shield' ),
					'recaptcha_v2' => 'Google reCAPTCHA v2',
					'recaptcha_v3' => 'Google reCAPTCHA v3',
					'hcaptcha'     => 'hCaptcha',
					'turnstile'    => 'Cloudflare Turnstile',
				),
			)
		);

		Settings::add_field(
			'captcha',
			array(
				'key'   => 'pro_captcha_site_key',
				'type'  => 'text',
				'label' => __( 'Site key', 'datametric-login-shield' ),
			)
		);

		Settings::add_field(
			'captcha',
			array(
				'key'         => 'pro_captcha_secret_key',
				'type'        => 'text',
				'label'       => __( 'Secret key', 'datametric-login-shield' ),
				'description' => __( 'When a provider is selected, its script loads on the login page and responses are verified with that provider.', 'datametric-login-shield' ),
			)
		);
	}

	/**
	 * Whether a provider is fully configured.
	 *
	 * @return bool
	 */
	private function is_configured() {
		$provider = (string) Options::get( 'pro_captcha_provider', '' );
		$providers = $this->providers();

		return '' !== $provider
			&& isset( $providers[ $provider ] )
			&& '' !== (string) Options::get( 'pro_captcha_site_key', '' )
			&& '' !== (string) Options::get( 'pro_captcha_secret_key', '' );
	}

	/**
	 * Enqueue the provider script on the login page.
	 *
	 * @return void
	 */
	public function enqueue() {
		$provider  = (string) Options::get( 'pro_captcha_provider', '' );
		$providers = $this->providers();
		$site_key  = (string) Options::get( 'pro_captcha_site_key', '' );

		$src = $providers[ $provider ]['script'];
		if ( false !== strpos( $src, '%s' ) ) {
			$src = sprintf( $src, rawurlencode( $site_key ) );
		}

		wp_enqueue_script( 'dmlsp-captcha', $src, array(), DMLS_VERSION, true );
	}

	/**
	 * Render the widget inside the login form.
	 *
	 * @return void
	 */
	public function render_widget() {
		$provider  = (string) Options::get( 'pro_captcha_provider', '' );
		$providers = $this->providers();
		$site_key  = (string) Options::get( 'pro_captcha_site_key', '' );
		$def       = $providers[ $provider ];

		echo '<div class="dmlsp-captcha" style="margin:0 0 16px">';
		if ( 'recaptcha_v3' === $provider ) {
			// v3 has no visible widget; fetch a token on submit into a hidden field.
			echo '<input type="hidden" name="g-recaptcha-response" id="dmlsp-v3-token" value="" />';
			$inline = 'document.addEventListener("submit",function(e){var f=e.target;if(f&&f.querySelector("#dmlsp-v3-token")&&!f.dmlspDone){e.preventDefault();grecaptcha.ready(function(){grecaptcha.execute(' . wp_json_encode( $site_key ) . ',{action:"login"}).then(function(t){document.getElementById("dmlsp-v3-token").value=t;f.dmlspDone=true;f.submit();});});}},true);';
			wp_add_inline_script( 'dmlsp-captcha', $inline );
		} else {
			printf( $def['markup'], esc_attr( $site_key ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- fixed markup template; site key escaped via esc_attr.
		}
		echo '</div>';
	}

	/**
	 * Verify the CAPTCHA response during authentication.
	 *
	 * @param mixed  $user     Auth result so far.
	 * @param string $username Username.
	 * @param string $password Password.
	 *
	 * @return mixed
	 */
	public function verify( $user, $username, $password ) {
		// Only enforce on the interactive login form submission.
		if ( ! isset( $_POST['wp-submit'] ) || '' === (string) $username ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- core login form; CAPTCHA is itself the anti-automation check.
			return $user;
		}

		$provider  = (string) Options::get( 'pro_captcha_provider', '' );
		$providers = $this->providers();
		if ( ! isset( $providers[ $provider ] ) ) {
			return $user;
		}
		$def = $providers[ $provider ];

		$response = isset( $_POST[ $def['field'] ] ) ? sanitize_text_field( wp_unslash( $_POST[ $def['field'] ] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- core login form.
		if ( '' === $response ) {
			return new WP_Error( 'dmlsp_captcha', __( 'Please complete the CAPTCHA.', 'datametric-login-shield' ) );
		}

		$result = wp_remote_post(
			$def['verify'],
			array(
				'timeout' => 5,
				'body'    => array(
					'secret'   => (string) Options::get( 'pro_captcha_secret_key', '' ),
					'response' => $response,
					'remoteip' => Ip::get(),
				),
			)
		);

		if ( is_wp_error( $result ) ) {
			// Fail-open on network error so a provider outage can't lock everyone out.
			return $user;
		}

		$body = json_decode( wp_remote_retrieve_body( $result ), true );
		$ok   = ! empty( $body['success'] );

		if ( 'recaptcha_v3' === $provider && $ok ) {
			$score = isset( $body['score'] ) ? (float) $body['score'] : 0;
			$ok    = $score >= 0.5;
		}

		if ( ! $ok ) {
			return new WP_Error( 'dmlsp_captcha', __( 'CAPTCHA verification failed. Please try again.', 'datametric-login-shield' ) );
		}

		return $user;
	}
}
