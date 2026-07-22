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
function dmls_uninstall_current_site() {
	global $wpdb;

	$settings = get_option( 'dmls_settings' );

	$purge = is_array( $settings ) && ! empty( $settings['uninstall_purge'] );

	if ( ! $purge ) {
		return;
	}

	delete_option( 'dmls_settings' );
	delete_option( 'dmls_db_version' );

	// Table names are built from the trusted $wpdb->prefix, not user input.
	$attempts = $wpdb->prefix . 'dmls_login_attempts';
	$events   = $wpdb->prefix . 'dmls_events';
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $attempts ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- custom table teardown on uninstall.
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $events ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- custom table teardown on uninstall.

	flush_rewrite_rules();
}

// Clear the scheduled maintenance event.
$dmls_timestamp = wp_next_scheduled( 'dmls_daily_maintenance' );
if ( $dmls_timestamp ) {
	wp_unschedule_event( $dmls_timestamp, 'dmls_daily_maintenance' );
}

if ( is_multisite() ) {
	$dmls_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);

	foreach ( (array) $dmls_site_ids as $dmls_site_id ) {
		switch_to_blog( $dmls_site_id );
		dmls_uninstall_current_site();
		restore_current_blog();
	}
} else {
	dmls_uninstall_current_site();
}
