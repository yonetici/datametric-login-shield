<?php
/**
 * Access hardening: close common login/enumeration bypass channels.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Modules\Hardening;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use Datametric\LoginShield\Container;
use Datametric\LoginShield\Contracts\ModuleInterface;
use Datametric\LoginShield\Support\Options;
use Datametric\LoginShield\Admin\Settings;

/**
 * A set of opt-in toggles that reinforce the "hide login" promise without
 * contacting any external service. Everything is fully reversible.
 */
class HardeningModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'hardening';
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
	public function register( Container $container ) {}

	/**
	 * {@inheritDoc}
	 */
	public function boot() {
		if ( is_admin() ) {
			$this->register_settings();
		}

		if ( Options::get( 'harden_rest_users', true ) ) {
			add_filter( 'rest_endpoints', array( $this, 'block_rest_user_routes' ) );
		}

		if ( Options::get( 'harden_author_enum', true ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_enumeration' ) );
		}

		if ( Options::get( 'harden_login_errors', true ) ) {
			add_filter( 'login_errors', array( $this, 'generic_login_error' ) );
		}

		if ( Options::get( 'harden_xmlrpc', false ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', array( $this, 'remove_pingback_methods' ) );
		}
	}

	/**
	 * Register the hardening fields (under the shared Protection tab).
	 *
	 * @return void
	 */
	private function register_settings() {
		Settings::add_tab( 'protection', __( 'Protection', 'datametric-login-shield' ), 20 );

		Settings::add_field(
			'protection',
			array(
				'key'         => 'harden_rest_users',
				'type'        => 'checkbox',
				'label'       => __( 'Block REST user enumeration', 'datametric-login-shield' ),
				'description' => __( 'Hide the /wp/v2/users REST endpoint from logged-out visitors.', 'datametric-login-shield' ),
				'default'     => true,
			)
		);

		Settings::add_field(
			'protection',
			array(
				'key'         => 'harden_author_enum',
				'type'        => 'checkbox',
				'label'       => __( 'Block author enumeration', 'datametric-login-shield' ),
				'description' => __( 'Prevent ?author=N scans that reveal usernames.', 'datametric-login-shield' ),
				'default'     => true,
			)
		);

		Settings::add_field(
			'protection',
			array(
				'key'         => 'harden_login_errors',
				'type'        => 'checkbox',
				'label'       => __( 'Generic login errors', 'datametric-login-shield' ),
				'description' => __( 'Show a single generic message so attackers cannot tell whether a username exists.', 'datametric-login-shield' ),
				'default'     => true,
			)
		);

		Settings::add_field(
			'protection',
			array(
				'key'         => 'harden_xmlrpc',
				'type'        => 'checkbox',
				'label'       => __( 'Disable XML-RPC', 'datametric-login-shield' ),
				'description' => __( 'Turn off XML-RPC. Leave off if you use the WordPress mobile app or Jetpack.', 'datametric-login-shield' ),
				'default'     => false,
			)
		);
	}

	/**
	 * Remove the users REST routes for unauthenticated requests.
	 *
	 * @param array $endpoints REST endpoint map.
	 *
	 * @return array
	 */
	public function block_rest_user_routes( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		foreach ( array( '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ) as $route ) {
			if ( isset( $endpoints[ $route ] ) ) {
				unset( $endpoints[ $route ] );
			}
		}

		return $endpoints;
	}

	/**
	 * Block ?author=N enumeration for logged-out visitors.
	 *
	 * @return void
	 */
	public function block_author_enumeration() {
		if ( is_user_logged_in() || is_admin() ) {
			return;
		}

		// Only react to the numeric ?author= query used for scanning.
		if ( isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only public request.
			$author = sanitize_text_field( wp_unslash( $_GET['author'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only request routing, no state change.
			if ( '' !== $author && is_numeric( $author ) ) {
				// 302 (temporary): a later toggle-off must not stay cached by clients.
				wp_safe_redirect( home_url( '/' ), 302 );
				exit;
			}
		}
	}

	/**
	 * Collapse all login errors into a single generic message.
	 *
	 * @param string $error Original error HTML.
	 *
	 * @return string
	 */
	public function generic_login_error( $error ) {
		return __( 'Login failed. Please check your credentials and try again.', 'datametric-login-shield' );
	}

	/**
	 * Remove pingback methods from the XML-RPC method list.
	 *
	 * @param array $methods XML-RPC methods.
	 *
	 * @return array
	 */
	public function remove_pingback_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );

		return $methods;
	}
}
