<?php
/**
 * Settings access with backward-compatibility for WPS Hide Login.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

/**
 * Reads and writes the namespaced `dmls_settings` option, while transparently
 * falling back to the legacy WPS Hide Login options (`whl_page`,
 * `whl_redirect_admin`) so that existing installs keep working after switching.
 */
class Options {

	const OPTION_KEY = 'dmls_settings';

	const DEFAULT_LOGIN_SLUG    = 'login';
	const DEFAULT_REDIRECT_SLUG = '404';

	/**
	 * Default settings.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults() {
		return array(
			'login_slug'      => '',
			'redirect_slug'   => '',
			'uninstall_purge' => false,

			// Brute-force protection.
			'bruteforce_enabled'      => true,
			'bruteforce_max_attempts' => 5,
			'bruteforce_lockout'      => 15,
			'bruteforce_allowlist'    => '',

			// Access hardening.
			'harden_rest_users'   => true,
			'harden_author_enum'  => true,
			'harden_login_errors' => true,
			'harden_xmlrpc'       => false,

			// Audit log.
			'audit_enabled'      => true,
			'audit_anonymize_ip' => false,
		);
	}

	/**
	 * Retrieve the full settings array (merged with defaults).
	 *
	 * @return array<string, mixed>
	 */
	public static function all() {
		$stored = get_option( self::OPTION_KEY, array() );

		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		return wp_parse_args( $stored, self::defaults() );
	}

	/**
	 * Retrieve a single setting.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Fallback when unset.
	 *
	 * @return mixed
	 */
	public static function get( $key, $default = null ) {
		$all = self::all();

		return array_key_exists( $key, $all ) && '' !== $all[ $key ] ? $all[ $key ] : $default;
	}

	/**
	 * Persist a partial set of settings (merged over the existing values).
	 *
	 * @param array<string, mixed> $values Values to merge.
	 *
	 * @return bool
	 */
	public static function update( array $values ) {
		$all = wp_parse_args( $values, self::all() );

		return update_option( self::OPTION_KEY, $all );
	}

	/**
	 * Resolve the effective login slug, honouring legacy options.
	 *
	 * Order: dmls_settings -> whl_page (site) -> network whl_page -> default.
	 *
	 * @return string
	 */
	public static function login_slug() {
		$slug = self::get( 'login_slug' );
		if ( ! empty( $slug ) ) {
			return $slug;
		}

		$legacy = get_option( 'whl_page' );
		if ( ! empty( $legacy ) ) {
			return $legacy;
		}

		if ( is_multisite() && self::is_network_active() ) {
			$network = get_site_option( 'whl_page', self::DEFAULT_LOGIN_SLUG );
			if ( ! empty( $network ) ) {
				return $network;
			}
		}

		return self::DEFAULT_LOGIN_SLUG;
	}

	/**
	 * Resolve the effective redirect slug, honouring legacy options.
	 *
	 * @return string
	 */
	public static function redirect_slug() {
		$slug = self::get( 'redirect_slug' );
		if ( ! empty( $slug ) ) {
			return $slug;
		}

		$legacy = get_option( 'whl_redirect_admin' );
		if ( ! empty( $legacy ) ) {
			return $legacy;
		}

		if ( is_multisite() && self::is_network_active() ) {
			$network = get_site_option( 'whl_redirect_admin', self::DEFAULT_REDIRECT_SLUG );
			if ( ! empty( $network ) ) {
				return $network;
			}
		}

		return self::DEFAULT_REDIRECT_SLUG;
	}

	/**
	 * Whether the plugin is network-activated. Safe to call early.
	 *
	 * @return bool
	 */
	public static function is_network_active() {
		if ( ! is_multisite() ) {
			return false;
		}

		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return is_plugin_active_for_network( DMLS_BASENAME );
	}

	/**
	 * One-time migration of legacy WPS Hide Login options into dmls_settings.
	 * Legacy options are left untouched so a rollback keeps working.
	 *
	 * @return void
	 */
	public static function maybe_migrate_legacy() {
		$stored = get_option( self::OPTION_KEY, false );

		// Only migrate when we have never stored our own settings yet.
		if ( is_array( $stored ) && ( ! empty( $stored['login_slug'] ) || ! empty( $stored['redirect_slug'] ) ) ) {
			return;
		}

		$legacy_page     = get_option( 'whl_page' );
		$legacy_redirect = get_option( 'whl_redirect_admin' );

		if ( empty( $legacy_page ) && empty( $legacy_redirect ) ) {
			return;
		}

		self::update(
			array(
				'login_slug'    => $legacy_page ? $legacy_page : '',
				'redirect_slug' => $legacy_redirect ? $legacy_redirect : '',
			)
		);
	}
}
