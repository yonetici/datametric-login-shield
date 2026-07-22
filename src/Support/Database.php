<?php
/**
 * Custom database tables and schema versioning.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

/**
 * Creates and upgrades the plugin's custom tables (login attempts, events).
 */
class Database {

	const DB_VERSION    = '1';
	const VERSION_OPTION = 'dls_db_version';

	/**
	 * Login-attempts table name for the current site.
	 *
	 * @return string
	 */
	public static function table_attempts() {
		global $wpdb;

		return $wpdb->prefix . 'dls_login_attempts';
	}

	/**
	 * Events (audit log) table name for the current site.
	 *
	 * @return string
	 */
	public static function table_events() {
		global $wpdb;

		return $wpdb->prefix . 'dls_events';
	}

	/**
	 * Create/upgrade tables on the current site via dbDelta.
	 *
	 * @return void
	 */
	public static function install() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$attempts        = self::table_attempts();
		$events          = self::table_events();

		$sql_attempts = "CREATE TABLE $attempts (
	id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	ip varchar(45) NOT NULL DEFAULT '',
	username varchar(180) NOT NULL DEFAULT '',
	created_at datetime NOT NULL,
	PRIMARY KEY  (id),
	KEY ip_time (ip, created_at)
) $charset_collate;";

		$sql_events = "CREATE TABLE $events (
	id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
	event_type varchar(32) NOT NULL DEFAULT '',
	ip varchar(45) NOT NULL DEFAULT '',
	username varchar(180) NOT NULL DEFAULT '',
	user_id bigint(20) unsigned NOT NULL DEFAULT 0,
	created_at datetime NOT NULL,
	PRIMARY KEY  (id),
	KEY type_time (event_type, created_at),
	KEY created_at (created_at)
) $charset_collate;";

		dbDelta( $sql_attempts );
		dbDelta( $sql_events );

		update_option( self::VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Install on every site of the network (or the single site).
	 *
	 * @return void
	 */
	public static function install_all() {
		if ( is_multisite() ) {
			$site_ids = get_sites( array( 'fields' => 'ids', 'number' => 0 ) );

			foreach ( (array) $site_ids as $site_id ) {
				switch_to_blog( $site_id );
				self::install();
				restore_current_blog();
			}
		} else {
			self::install();
		}
	}

	/**
	 * Run an upgrade if the stored schema version is out of date.
	 *
	 * @return void
	 */
	public static function maybe_upgrade() {
		if ( get_option( self::VERSION_OPTION ) !== self::DB_VERSION ) {
			self::install();
		}
	}

	/**
	 * Drop the tables on the current site (used on uninstall when purge is on).
	 *
	 * @return void
	 */
	public static function drop() {
		global $wpdb;

		$attempts = self::table_attempts();
		$events   = self::table_events();

		// Table identifiers cannot be parameterized; names are built from the
		// trusted $wpdb->prefix, not user input.
		$wpdb->query( "DROP TABLE IF EXISTS $attempts" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery
		$wpdb->query( "DROP TABLE IF EXISTS $events" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery

		delete_option( self::VERSION_OPTION );
	}
}
