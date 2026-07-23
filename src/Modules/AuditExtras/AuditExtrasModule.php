<?php
/**
 * Pro module: unlimited audit history, CSV export and email alerts.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Modules\AuditExtras;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use Datametric\LoginShield\Container;
use Datametric\LoginShield\Contracts\ModuleInterface;
use Datametric\LoginShield\Admin\Settings;
use Datametric\LoginShield\Support\Options;
use Datametric\LoginShield\Support\Database;

/**
 * Extends the free audit log: configurable/unlimited retention, CSV export and
 * email alerts on lockouts and administrator logins.
 */
class AuditExtrasModule implements ModuleInterface {

	const EXPORT_ACTION = 'dmlsp_export_audit';

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'pro-audit';
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
		// Override the free 7-day retention with the Pro setting.
		add_filter( 'dmls_audit_retention_days', array( $this, 'retention_days' ) );

		// Alerts.
		add_action( 'dmls_event_logged', array( $this, 'maybe_alert' ), 10, 4 );

		// CSV export endpoint.
		add_action( 'admin_post_' . self::EXPORT_ACTION, array( $this, 'export_csv' ) );

		if ( is_admin() ) {
			$this->register_settings();
		}
	}

	/**
	 * Register the Audit Pro tab (custom render adds the export button).
	 *
	 * @return void
	 */
	private function register_settings() {
		Settings::add_tab( 'audit-pro', __( 'Alerts & Export', 'datametric-login-shield' ), 31, array( $this, 'render_tab' ) );

		Settings::add_field(
			'audit-pro',
			array(
				'key'         => 'pro_audit_retention',
				'type'        => 'number',
				'label'       => __( 'Retention (days)', 'datametric-login-shield' ),
				'description' => __( 'How long to keep audit events. Set to 0 to keep them forever.', 'datametric-login-shield' ),
				'default'     => 30,
				'min'         => 0,
				'max'         => 3650,
			)
		);

		Settings::add_field(
			'audit-pro',
			array(
				'key'         => 'pro_audit_alert_email',
				'type'        => 'text',
				'label'       => __( 'Alert email', 'datametric-login-shield' ),
				'description' => __( 'Where to send security alerts (defaults to the admin email).', 'datametric-login-shield' ),
			)
		);

		Settings::add_field(
			'audit-pro',
			array(
				'key'     => 'pro_audit_alert_lockout',
				'type'    => 'checkbox',
				'label'   => __( 'Email me on lockouts', 'datametric-login-shield' ),
				'default' => false,
			)
		);

		Settings::add_field(
			'audit-pro',
			array(
				'key'     => 'pro_audit_alert_admin_login',
				'type'    => 'checkbox',
				'label'   => __( 'Email me when an administrator logs in', 'datametric-login-shield' ),
				'default' => false,
			)
		);
	}

	/**
	 * Retention in days (0 = unlimited).
	 *
	 * @param int $default Free default.
	 *
	 * @return int
	 */
	public function retention_days( $default ) {
		return (int) Options::get( 'pro_audit_retention', 30 );
	}

	/* --------------------------------------------------------------------- *
	 * Alerts
	 * --------------------------------------------------------------------- */

	/**
	 * Send an email alert for notable events.
	 *
	 * @param string $type     Event type.
	 * @param string $ip       Client IP.
	 * @param string $username Username.
	 * @param int    $user_id  User id.
	 *
	 * @return void
	 */
	public function maybe_alert( $type, $ip, $username, $user_id ) {
		$send = false;

		if ( 'lockout' === $type && Options::get( 'pro_audit_alert_lockout', false ) ) {
			$send = true;
		}

		if ( 'login_success' === $type
			&& Options::get( 'pro_audit_alert_admin_login', false )
			&& $user_id
			&& user_can( (int) $user_id, 'manage_options' ) ) {
			$send = true;
		}

		if ( ! $send ) {
			return;
		}

		$to = trim( (string) Options::get( 'pro_audit_alert_email', '' ) );
		if ( '' === $to || ! is_email( $to ) ) {
			$to = get_option( 'admin_email' );
		}

		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$labels  = array(
			'lockout'       => __( 'IP locked out', 'datametric-login-shield' ),
			'login_success' => __( 'Administrator login', 'datametric-login-shield' ),
		);
		$label   = isset( $labels[ $type ] ) ? $labels[ $type ] : $type;
		/* translators: 1: site name, 2: event label. */
		$subject = sprintf( __( '[%1$s] Security alert: %2$s', 'datametric-login-shield' ), $site, $label );
		$body    = sprintf(
			/* translators: 1: event label, 2: username, 3: IP, 4: date. */
			__( "Event: %1\$s\nUser: %2\$s\nIP: %3\$s\nTime: %4\$s", 'datametric-login-shield' ),
			$label,
			'' !== $username ? $username : '—',
			'' !== $ip ? $ip : '—',
			gmdate( 'Y-m-d H:i:s' ) . ' UTC'
		);

		wp_mail( $to, $subject, $body );
	}

	/* --------------------------------------------------------------------- *
	 * Admin tab + CSV export
	 * --------------------------------------------------------------------- */

	/**
	 * Render the Alerts & Export tab: settings form + export button.
	 *
	 * @return void
	 */
	public function render_tab() {
		echo '<form method="post" class="dls-form">';
		wp_nonce_field( 'dmls_save_settings', 'dmls_nonce' );
		echo '<input type="hidden" name="dmls_action" value="save_fields" />';
		echo '<input type="hidden" name="dmls_tab" value="audit-pro" />';
		Settings::render_fields( 'audit-pro' );
		submit_button( __( 'Save', 'datametric-login-shield' ) );
		echo '</form>';

		echo '<hr />';
		$url = wp_nonce_url( admin_url( 'admin-post.php?action=' . self::EXPORT_ACTION ), self::EXPORT_ACTION );
		echo '<p><a class="button button-secondary" href="' . esc_url( $url ) . '">' . esc_html__( 'Export all events to CSV', 'datametric-login-shield' ) . '</a></p>';
	}

	/**
	 * Stream the full events table as a CSV download.
	 *
	 * @return void
	 */
	public function export_csv() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'datametric-login-shield' ) );
		}

		check_admin_referer( self::EXPORT_ACTION );

		global $wpdb;
		$table = Database::table_events();
		$rows  = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom log table, admin export.
			$wpdb->prepare( 'SELECT created_at, event_type, username, user_id, ip FROM %i ORDER BY created_at DESC', $table )
		);

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=login-audit-' . gmdate( 'Ymd-His' ) . '.csv' );

		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, array( 'created_at_utc', 'event', 'username', 'user_id', 'ip' ) );
		if ( is_array( $rows ) ) {
			foreach ( $rows as $row ) {
				fputcsv(
					$out,
					array(
						$this->csv_safe( $row->created_at ),
						$this->csv_safe( $row->event_type ),
						$this->csv_safe( $row->username ),
						$this->csv_safe( $row->user_id ),
						$this->csv_safe( $row->ip ),
					)
				);
			}
		}
		fclose( $out );
		exit;
	}

	/**
	 * Neutralize CSV formula injection: usernames are attacker-controlled, so a
	 * cell beginning with a formula trigger is prefixed with an apostrophe.
	 *
	 * @param mixed $value Cell value.
	 *
	 * @return string
	 */
	private function csv_safe( $value ) {
		$value = (string) $value;
		if ( '' !== $value && in_array( $value[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
			return "'" . $value;
		}

		return $value;
	}
}
