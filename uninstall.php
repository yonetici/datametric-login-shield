<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * Only removes data when the admin opted in (Advanced tab -> "Delete all data").
 * Legacy WPS Hide Login options are left untouched so switching back keeps working.
 *
 * @package Datametric\LoginShield
 * @license GPL-2.0-or-later
 */

// If uninstall not called from WordPress, then exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Remove plugin options for the current site.
 *
 * @return void
 */
function dls_uninstall_current_site() {
	global $wpdb;

	$settings = get_option( 'dls_settings' );

	$purge = is_array( $settings ) && ! empty( $settings['uninstall_purge'] );

	if ( ! $purge ) {
		return;
	}

	delete_option( 'dls_settings' );
	delete_option( 'dls_db_version' );

	// Table names are built from the trusted $wpdb->prefix, not user input.
	$attempts = $wpdb->prefix . 'dls_login_attempts';
	$events   = $wpdb->prefix . 'dls_events';
	$wpdb->query( "DROP TABLE IF EXISTS $attempts" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
	$wpdb->query( "DROP TABLE IF EXISTS $events" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange

	flush_rewrite_rules();
}

// Clear the scheduled maintenance event.
$dls_timestamp = wp_next_scheduled( 'dls_daily_maintenance' );
if ( $dls_timestamp ) {
	wp_unschedule_event( $dls_timestamp, 'dls_daily_maintenance' );
}

if ( is_multisite() ) {
	$dls_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);

	foreach ( (array) $dls_site_ids as $dls_site_id ) {
		switch_to_blog( $dls_site_id );
		dls_uninstall_current_site();
		restore_current_blog();
	}
} else {
	dls_uninstall_current_site();
}
