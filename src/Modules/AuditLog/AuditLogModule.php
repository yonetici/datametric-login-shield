<?php
/**
 * Login audit log: record and display login-related events.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Modules\AuditLog;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use WP_User;
use Datametric\LoginShield\Container;
use Datametric\LoginShield\Contracts\ModuleInterface;
use Datametric\LoginShield\Support\Options;
use Datametric\LoginShield\Support\Ip;
use Datametric\LoginShield\Support\Database;
use Datametric\LoginShield\Admin\Settings;

/**
 * Records successful/failed logins, logouts and lockouts, and renders a
 * paginated, filterable event table. Free tier keeps 7 days of history.
 */
class AuditLogModule implements ModuleInterface {

	const RETENTION_DAYS = 7;
	const PER_PAGE       = 20;

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'audit-log';
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
		// Expose this module so others can record events directly.
		$container->set( 'audit_log', $this );
	}

	/**
	 * Record an event directly (public API for other modules).
	 *
	 * @param string $type     Event type (login_success|login_failed|lockout|logout).
	 * @param string $username Username.
	 * @param int    $user_id  User id.
	 *
	 * @return void
	 */
	public function record( $type, $username = '', $user_id = 0 ) {
		if ( ! Options::get( 'audit_enabled', true ) ) {
			return;
		}

		$this->insert_event( $type, (string) $username, (int) $user_id );
	}

	/**
	 * {@inheritDoc}
	 */
	public function boot() {
		if ( is_admin() ) {
			$this->register_settings();
			add_action( 'admin_init', array( $this, 'register_privacy_content' ) );
		}

		add_action( 'dmls_daily_maintenance', array( $this, 'prune' ) );

		if ( ! Options::get( 'audit_enabled', true ) ) {
			return;
		}

		add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
		add_action( 'wp_logout', array( $this, 'on_logout' ) );
		add_action( 'dmls_lockout', array( $this, 'on_lockout' ), 10, 2 );
	}

	/**
	 * Register the Audit Log tab (custom renderer) and its settings.
	 *
	 * @return void
	 */
	private function register_settings() {
		Settings::add_tab( 'audit-log', __( 'Audit Log', 'datametric-login-shield' ), 30, array( $this, 'render_tab' ) );

		Settings::add_field(
			'audit-log',
			array(
				'key'         => 'audit_enabled',
				'type'        => 'checkbox',
				'label'       => __( 'Enable logging', 'datametric-login-shield' ),
				'description' => __( 'Record login, logout and lockout events.', 'datametric-login-shield' ),
				'default'     => true,
			)
		);

		Settings::add_field(
			'audit-log',
			array(
				'key'         => 'audit_anonymize_ip',
				'type'        => 'checkbox',
				'label'       => __( 'Anonymize IP addresses', 'datametric-login-shield' ),
				'description' => __( 'Store masked IPs (e.g. 203.0.113.0) for extra privacy.', 'datametric-login-shield' ),
				'default'     => false,
			)
		);
	}

	/**
	 * Register suggested privacy-policy text with WordPress' policy generator.
	 *
	 * @return void
	 */
	public function register_privacy_content() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}

		$content = __( 'Datametric Login Shield stores login-related events (login, failed login, lockout, logout) including IP address, username and timestamp for up to 7 days, and failed login attempts for up to 24 hours, in order to protect the site against brute-force attacks. This data is stored only in this site\'s database and is not shared with any third party.', 'datametric-login-shield' );

		wp_add_privacy_policy_content(
			__( 'Datametric Login Shield', 'datametric-login-shield' ),
			wp_kses_post( wpautop( $content ) )
		);
	}

	/*
	 * ---------------------------------------------------------------------
	 * Event recording
	 * ---------------------------------------------------------------------
	 */

	/**
	 * Record a successful login.
	 *
	 * @param string       $user_login Username.
	 * @param WP_User|null $user       User object.
	 *
	 * @return void
	 */
	public function on_login( $user_login, $user = null ) {
		$user_id = ( $user instanceof WP_User ) ? (int) $user->ID : 0;
		$this->insert_event( 'login_success', (string) $user_login, $user_id );
	}

	/**
	 * Record a failed login.
	 *
	 * @param string $username Attempted username.
	 *
	 * @return void
	 */
	public function on_login_failed( $username ) {
		$this->insert_event( 'login_failed', (string) $username, 0 );
	}

	/**
	 * Record a logout.
	 *
	 * @param int $user_id User id (available WP 5.5+).
	 *
	 * @return void
	 */
	public function on_logout( $user_id = 0 ) {
		$this->insert_event( 'logout', '', (int) $user_id );
	}

	/**
	 * Record a lockout.
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Attempted username.
	 *
	 * @return void
	 */
	public function on_lockout( $ip, $username = '' ) {
		$this->insert_event( 'lockout', (string) $username, 0, $ip );
	}

	/**
	 * Insert an event row. Silently no-ops on error (logging must never break login).
	 *
	 * @param string $type     Event type.
	 * @param string $username Username.
	 * @param int    $user_id  User id.
	 * @param string $ip       Optional explicit IP; defaults to the request IP.
	 *
	 * @return void
	 */
	private function insert_event( $type, $username, $user_id, $ip = null ) {
		global $wpdb;

		$ip = ( null === $ip ) ? Ip::get() : $ip;

		if ( Options::get( 'audit_anonymize_ip', false ) ) {
			$ip = Ip::anonymize( $ip );
		}

		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom log table; $wpdb->insert() escapes values internally.
			Database::table_events(),
			array(
				'event_type' => substr( $type, 0, 32 ),
				'ip'         => (string) $ip,
				'username'   => substr( (string) $username, 0, 180 ),
				'user_id'    => (int) $user_id,
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s', '%s', '%d', '%s' )
		);

		/**
		 * Fires after a login event is recorded. Add-ons use this for alerts.
		 *
		 * @param string $type     Event type (login_success|login_failed|lockout|logout).
		 * @param string $ip       Client IP (possibly anonymized).
		 * @param string $username Username.
		 * @param int    $user_id  User id.
		 */
		do_action( 'dmls_event_logged', $type, (string) $ip, (string) $username, (int) $user_id );
	}

	/**
	 * Delete events older than the retention window.
	 *
	 * @return void
	 */
	public function prune() {
		global $wpdb;

		/**
		 * Filter the audit-log retention in days. An add-on may raise this or
		 * return 0 / a negative value to keep events indefinitely.
		 *
		 * @param int $days Default retention (free tier).
		 */
		$days = (int) apply_filters( 'dmls_audit_retention_days', self::RETENTION_DAYS );

		if ( $days <= 0 ) {
			return; // Keep everything (e.g. Pro unlimited history).
		}

		$table = Database::table_events();
		$since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom log table, no core API.
			$wpdb->prepare( 'DELETE FROM %i WHERE created_at < %s', $table, $since )
		);
	}

	/*
	 * ---------------------------------------------------------------------
	 * Admin rendering
	 * ---------------------------------------------------------------------
	 */

	/**
	 * Human labels for event types.
	 *
	 * @return array<string, string>
	 */
	private function type_labels() {
		return array(
			'login_success' => __( 'Login', 'datametric-login-shield' ),
			'login_failed'  => __( 'Failed login', 'datametric-login-shield' ),
			'lockout'       => __( 'Lockout', 'datametric-login-shield' ),
			'logout'        => __( 'Logout', 'datametric-login-shield' ),
		);
	}

	/**
	 * Render the Audit Log tab: settings form + filter + events table.
	 *
	 * @return void
	 */
	public function render_tab() {
		$labels = $this->type_labels();

		// Settings form (enable / anonymize).
		echo '<form method="post" class="dls-form">';
		wp_nonce_field( 'dmls_save_settings', 'dmls_nonce' );
		echo '<input type="hidden" name="dmls_action" value="save_fields" />';
		echo '<input type="hidden" name="dmls_tab" value="audit-log" />';
		Settings::render_fields( 'audit-log' );
		submit_button( __( 'Save logging settings', 'datametric-login-shield' ) );
		echo '</form>';

		echo '<hr />';

		// Read filter + pagination from the query (read-only, no nonce needed).
		$filter = '';
		if ( isset( $_GET['event_type'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$candidate = sanitize_key( wp_unslash( $_GET['event_type'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only request routing, no state change.
			if ( isset( $labels[ $candidate ] ) ) {
				$filter = $candidate;
			}
		}

		$paged = isset( $_GET['dmls_paged'] ) ? max( 1, absint( wp_unslash( $_GET['dmls_paged'] ) ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$total  = $this->count_events( $filter );
		$pages  = (int) ceil( $total / self::PER_PAGE );
		$offset = ( $paged - 1 ) * self::PER_PAGE;
		$events = $this->get_events( $filter, self::PER_PAGE, $offset );

		// Filter dropdown.
		echo '<form method="get" class="dls-log-filter">';
		echo '<input type="hidden" name="page" value="datametric-login-shield" />';
		echo '<input type="hidden" name="tab" value="audit-log" />';
		echo '<label for="dmls_event_type" class="screen-reader-text">' . esc_html__( 'Filter by event', 'datametric-login-shield' ) . '</label>';
		echo '<select name="event_type" id="dmls_event_type">';
		echo '<option value="">' . esc_html__( 'All events', 'datametric-login-shield' ) . '</option>';
		foreach ( $labels as $type => $label ) {
			echo '<option value="' . esc_attr( $type ) . '" ' . selected( $filter, $type, false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select> ';
		submit_button( __( 'Filter', 'datametric-login-shield' ), 'secondary', '', false );
		echo '</form>';

		// Events table.
		echo '<table class="widefat striped dls-log-table">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Date', 'datametric-login-shield' ) . '</th>';
		echo '<th>' . esc_html__( 'Event', 'datametric-login-shield' ) . '</th>';
		echo '<th>' . esc_html__( 'User', 'datametric-login-shield' ) . '</th>';
		echo '<th>' . esc_html__( 'IP address', 'datametric-login-shield' ) . '</th>';
		echo '</tr></thead><tbody>';

		if ( empty( $events ) ) {
			echo '<tr><td colspan="4">' . esc_html__( 'No events recorded yet.', 'datametric-login-shield' ) . '</td></tr>';
		} else {
			foreach ( $events as $event ) {
				$local = get_date_from_gmt( $event->created_at, 'Y-m-d H:i:s' );
				$label = isset( $labels[ $event->event_type ] ) ? $labels[ $event->event_type ] : $event->event_type;
				echo '<tr>';
				echo '<td>' . esc_html( $local ) . '</td>';
				echo '<td>' . esc_html( $label ) . '</td>';
				echo '<td>' . esc_html( '' !== $event->username ? $event->username : '—' ) . '</td>';
				echo '<td>' . esc_html( '' !== $event->ip ? $event->ip : '—' ) . '</td>';
				echo '</tr>';
			}
		}

		echo '</tbody></table>';

		// Pagination.
		if ( $pages > 1 ) {
			$base = add_query_arg(
				array(
					'page'       => 'datametric-login-shield',
					'tab'        => 'audit-log',
					'event_type' => $filter,
					'dmls_paged'  => '%#%',
				),
				admin_url( 'admin.php' )
			);

			$links = paginate_links(
				array(
					'base'      => $base,
					'format'    => '',
					'current'   => $paged,
					'total'     => $pages,
					'prev_text' => '&laquo;',
					'next_text' => '&raquo;',
				)
			);

			if ( $links ) {
				echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post( $links ) . '</div></div>';
			}
		}

		echo '<p class="description">';
		printf(
			/* translators: %d: number of days events are kept. */
			esc_html__( 'Events are kept for %d days.', 'datametric-login-shield' ),
			(int) self::RETENTION_DAYS
		);
		echo '</p>';
	}

	/**
	 * Count events, optionally filtered by type. Fail-safe (returns 0 on error).
	 *
	 * @param string $filter Event type or empty for all.
	 *
	 * @return int
	 */
	private function count_events( $filter ) {
		global $wpdb;

		$table = Database::table_events();

		if ( '' !== $filter ) {
			$count = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom log table, no core API.
				$wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE event_type = %s', $table, $filter )
			);
		} else {
			$count = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom log table, no core API.
				$wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table )
			);
		}

		return $wpdb->last_error ? 0 : (int) $count;
	}

	/**
	 * Fetch a page of events.
	 *
	 * @param string $filter Event type or empty for all.
	 * @param int    $limit  Rows per page.
	 * @param int    $offset Offset.
	 *
	 * @return array<int, object>
	 */
	private function get_events( $filter, $limit, $offset ) {
		global $wpdb;

		$table = Database::table_events();

		if ( '' !== $filter ) {
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom log table, no core API.
				$wpdb->prepare( 'SELECT event_type, ip, username, user_id, created_at FROM %i WHERE event_type = %s ORDER BY created_at DESC LIMIT %d OFFSET %d', $table, $filter, $limit, $offset )
			);
		} else {
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom log table, no core API.
				$wpdb->prepare( 'SELECT event_type, ip, username, user_id, created_at FROM %i ORDER BY created_at DESC LIMIT %d OFFSET %d', $table, $limit, $offset )
			);
		}

		return is_array( $rows ) ? $rows : array();
	}
}
