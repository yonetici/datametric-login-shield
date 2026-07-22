<?php
/**
 * Brute-force protection: throttle and lock out repeated failed logins.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Modules\BruteForce;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use WP_Error;
use WP_User;
use Datametric\LoginShield\Container;
use Datametric\LoginShield\Contracts\ModuleInterface;
use Datametric\LoginShield\Support\Options;
use Datametric\LoginShield\Support\Ip;
use Datametric\LoginShield\Support\Database;
use Datametric\LoginShield\Admin\Settings;

/**
 * Records failed logins per IP and blocks further attempts once a threshold is
 * reached, for a configurable lockout window.
 *
 * Design guarantees:
 *  - FAIL-OPEN: any database error results in NOT blocking (never lock everyone out).
 *  - Lockouts auto-expire; an allowlist protects the site owner's IP.
 */
class BruteForceModule implements ModuleInterface {

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'brute-force';
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

		if ( ! Options::get( 'bruteforce_enabled', true ) ) {
			return;
		}

		add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 3 );
		add_action( 'wp_login_failed', array( $this, 'record_failure' ) );
		add_action( 'wp_login', array( $this, 'clear_attempts' ), 10, 2 );
		add_action( 'dmls_daily_maintenance', array( $this, 'prune' ) );
	}

	/**
	 * Register the Protection tab and brute-force fields.
	 *
	 * @return void
	 */
	private function register_settings() {
		Settings::add_tab( 'protection', __( 'Protection', 'datametric-login-shield' ), 20 );

		Settings::add_field(
			'protection',
			array(
				'key'         => 'bruteforce_enabled',
				'type'        => 'checkbox',
				'label'       => __( 'Brute-force protection', 'datametric-login-shield' ),
				'description' => __( 'Block repeated failed login attempts.', 'datametric-login-shield' ),
				'default'     => true,
			)
		);

		Settings::add_field(
			'protection',
			array(
				'key'         => 'bruteforce_max_attempts',
				'type'        => 'number',
				'label'       => __( 'Max failed attempts', 'datametric-login-shield' ),
				'description' => __( 'Lock out an IP after this many failed logins.', 'datametric-login-shield' ),
				'default'     => 5,
				'min'         => 1,
				'max'         => 100,
			)
		);

		Settings::add_field(
			'protection',
			array(
				'key'         => 'bruteforce_lockout',
				'type'        => 'number',
				'label'       => __( 'Lockout minutes', 'datametric-login-shield' ),
				'description' => __( 'How long a locked-out IP must wait.', 'datametric-login-shield' ),
				'default'     => 15,
				'min'         => 1,
				'max'         => 1440,
			)
		);

		Settings::add_field(
			'protection',
			array(
				'key'         => 'bruteforce_allowlist',
				'type'        => 'textarea',
				'label'       => __( 'Allowlisted IPs', 'datametric-login-shield' ),
				'description' => __( 'One IP per line. These IPs are never locked out — add your own to avoid locking yourself out.', 'datametric-login-shield' ),
				'default'     => '',
				'placeholder' => "203.0.113.10\n198.51.100.24",
			)
		);
	}

	/**
	 * Block authentication when the client IP is currently locked out.
	 *
	 * @param WP_User|WP_Error|null $user     Current auth result.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 *
	 * @return WP_User|WP_Error|null
	 */
	public function check_lockout( $user, $username, $password ) {
		// Only intervene on real login attempts (a username was submitted).
		if ( '' === (string) $username ) {
			return $user;
		}

		$ip = Ip::get();
		if ( '' === $ip || $this->is_allowlisted( $ip ) ) {
			return $user;
		}

		if ( $this->is_locked( $ip ) ) {
			return new WP_Error(
				'dmls_locked',
				__( 'Too many failed login attempts. Please try again later.', 'datametric-login-shield' )
			);
		}

		return $user;
	}

	/**
	 * Record a failed login attempt.
	 *
	 * @param string $username Attempted username.
	 *
	 * @return void
	 */
	public function record_failure( $username ) {
		global $wpdb;

		$ip = Ip::get();
		if ( '' === $ip || $this->is_allowlisted( $ip ) ) {
			return;
		}

		$table = Database::table_attempts();

		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$table,
			array(
				'ip'         => $ip,
				'username'   => substr( (string) $username, 0, 180 ),
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s', '%s' )
		);

		// If this failure just reached the threshold, announce a lockout once.
		if ( $this->count_recent( $ip ) === (int) $this->max_attempts() ) {
			/**
			 * Fires when an IP crosses the lockout threshold.
			 *
			 * @param string $ip       Client IP.
			 * @param string $username Attempted username.
			 */
			do_action( 'dmls_lockout', $ip, (string) $username );
		}
	}

	/**
	 * Clear an IP's attempts after a successful login.
	 *
	 * @param string       $user_login Username.
	 * @param WP_User|null $user       User object.
	 *
	 * @return void
	 */
	public function clear_attempts( $user_login, $user = null ) {
		global $wpdb;

		$ip = Ip::get();
		if ( '' === $ip ) {
			return;
		}

		$table = Database::table_attempts();

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare( "DELETE FROM $table WHERE ip = %s", $ip ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is trusted.
		);
	}

	/**
	 * Whether an IP is currently locked out.
	 *
	 * @param string $ip Client IP.
	 *
	 * @return bool
	 */
	private function is_locked( $ip ) {
		return $this->count_recent( $ip ) >= (int) $this->max_attempts();
	}

	/**
	 * Count failed attempts for an IP within the lockout window. Fail-open on error.
	 *
	 * @param string $ip Client IP.
	 *
	 * @return int
	 */
	private function count_recent( $ip ) {
		global $wpdb;

		$table   = Database::table_attempts();
		$minutes = (int) $this->lockout_minutes();
		$since   = gmdate( 'Y-m-d H:i:s', time() - ( $minutes * MINUTE_IN_SECONDS ) );

		$count = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE ip = %s AND created_at > %s", $ip, $since ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is trusted.
		);

		// FAIL-OPEN: on any DB error, report zero so nobody is blocked.
		if ( $wpdb->last_error ) {
			return 0;
		}

		return (int) $count;
	}

	/**
	 * Remove attempts older than 24 hours.
	 *
	 * @return void
	 */
	public function prune() {
		global $wpdb;

		$table = Database::table_attempts();
		$since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare( "DELETE FROM $table WHERE created_at < %s", $since ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is trusted.
		);
	}

	/**
	 * Whether an IP is on the allowlist.
	 *
	 * @param string $ip Client IP.
	 *
	 * @return bool
	 */
	private function is_allowlisted( $ip ) {
		$raw = (string) Options::get( 'bruteforce_allowlist', '' );
		if ( '' === trim( $raw ) ) {
			return false;
		}

		$list = preg_split( '/[\r\n,]+/', $raw );
		$list = array_filter( array_map( 'trim', (array) $list ) );

		return in_array( $ip, $list, true );
	}

	/**
	 * Configured max attempts.
	 *
	 * @return int
	 */
	private function max_attempts() {
		return max( 1, (int) Options::get( 'bruteforce_max_attempts', 5 ) );
	}

	/**
	 * Configured lockout window in minutes.
	 *
	 * @return int
	 */
	private function lockout_minutes() {
		return max( 1, (int) Options::get( 'bruteforce_lockout', 15 ) );
	}
}
