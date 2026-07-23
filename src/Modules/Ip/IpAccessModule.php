<?php
/**
 * Pro module: IP allow / deny lists for login.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Modules\Ip;

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
 * Restricts who may reach the login by client IP.
 *
 * Allow list (when non-empty) = only those IPs/ranges may log in. Deny list =
 * these IPs/ranges are always blocked. IPv4 and simple CIDR (a.b.c.d/nn) are
 * supported. Fail-open: if the client IP can't be determined, no block is
 * applied so the owner is never locked out by a proxy misconfiguration.
 */
class IpAccessModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'pro-ip-access';
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

		add_filter( 'authenticate', array( $this, 'check_ip' ), 5, 3 );
	}

	/**
	 * Register the IP Access settings tab.
	 *
	 * @return void
	 */
	private function register_settings() {
		Settings::add_tab( 'ip-access', __( 'IP Access', 'datametric-login-shield' ), 26 );

		Settings::add_field(
			'ip-access',
			array(
				'key'         => 'pro_ip_allow',
				'type'        => 'textarea',
				'label'       => __( 'Allow list', 'datametric-login-shield' ),
				'description' => __( 'One IP or CIDR range per line. When set, ONLY these may log in. Leave empty to allow all.', 'datametric-login-shield' ),
				'default'     => '',
				'placeholder' => "203.0.113.10\n198.51.100.0/24",
			)
		);

		Settings::add_field(
			'ip-access',
			array(
				'key'         => 'pro_ip_deny',
				'type'        => 'textarea',
				'label'       => __( 'Deny list', 'datametric-login-shield' ),
				'description' => __( 'One IP or CIDR range per line. These are always blocked from logging in.', 'datametric-login-shield' ),
				'default'     => '',
				'placeholder' => '192.0.2.44',
			)
		);
	}

	/**
	 * Block authentication from disallowed IPs.
	 *
	 * @param mixed  $user     Auth result so far.
	 * @param string $username Submitted username.
	 * @param string $password Submitted password.
	 *
	 * @return mixed
	 */
	public function check_ip( $user, $username, $password ) {
		if ( defined( 'DMLS_DISABLE_IP_ACCESS' ) && DMLS_DISABLE_IP_ACCESS ) {
			return $user; // Emergency escape hatch for an IP-rule lockout.
		}

		if ( '' === (string) $username ) {
			return $user;
		}

		$ip = Ip::get();
		if ( '' === $ip ) {
			return $user; // Fail-open: cannot identify the client.
		}

		$allow = $this->parse_list( Options::get( 'pro_ip_allow', '' ) );
		$deny  = $this->parse_list( Options::get( 'pro_ip_deny', '' ) );

		if ( ! empty( $allow ) && ! $this->ip_in_list( $ip, $allow ) ) {
			return $this->blocked();
		}

		if ( ! empty( $deny ) && $this->ip_in_list( $ip, $deny ) ) {
			return $this->blocked();
		}

		return $user;
	}

	/**
	 * Generic block error (does not reveal the rule).
	 *
	 * @return WP_Error
	 */
	private function blocked() {
		return new WP_Error( 'dmlsp_ip_blocked', __( 'Login from your network is not allowed.', 'datametric-login-shield' ) );
	}

	/**
	 * Parse a textarea list into trimmed non-empty lines.
	 *
	 * @param string $raw Raw textarea value.
	 *
	 * @return string[]
	 */
	private function parse_list( $raw ) {
		$lines = preg_split( '/[\r\n]+/', (string) $raw );

		return array_values( array_filter( array_map( 'trim', (array) $lines ) ) );
	}

	/**
	 * Whether an IP matches any entry (exact or CIDR).
	 *
	 * @param string   $ip   Client IP.
	 * @param string[] $list Entries.
	 *
	 * @return bool
	 */
	private function ip_in_list( $ip, array $list ) {
		foreach ( $list as $entry ) {
			if ( false !== strpos( $entry, '/' ) ) {
				if ( $this->cidr_match( $ip, $entry ) ) {
					return true;
				}
			} elseif ( $entry === $ip ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * IPv4 CIDR match.
	 *
	 * @param string $ip   Client IP.
	 * @param string $cidr Range like 198.51.100.0/24.
	 *
	 * @return bool
	 */
	private function cidr_match( $ip, $cidr ) {
		list( $subnet, $bits ) = array_pad( explode( '/', $cidr, 2 ), 2, '' );

		// Reject malformed masks (e.g. "1.2.3.4/" or "/abc") instead of treating
		// them as /0, which would silently match every address.
		if ( '' === $bits || ! ctype_digit( (string) $bits ) ) {
			return false;
		}
		$bits = (int) $bits;
		if ( $bits < 1 || $bits > 32 ) {
			return false;
		}

		$ip_long     = ip2long( $ip );
		$subnet_long = ip2long( $subnet );
		if ( false === $ip_long || false === $subnet_long ) {
			return false;
		}

		$mask = -1 << ( 32 - $bits );

		return ( $ip_long & $mask ) === ( $subnet_long & $mask );
	}
}
