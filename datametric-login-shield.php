<?php
/**
 * Plugin Name:       Datametric Login Shield
 * Plugin URI:        https://www.datametric.com.tr/login-shield
 * Description:        Hide your WordPress login URL and block access to wp-login.php and the wp-admin directory for logged-out visitors. Modular login-security layer by Datametric.
 * Version:           1.1.0
 * Author:            Datametric
 * Author URI:        https://www.datametric.com.tr
 * Requires at least: 5.3
 * Tested up to:      6.9
 * Requires PHP:      7.2
 * Text Domain:       datametric-login-shield
 * Domain Path:       /languages
 * License:           GPLv2 or later
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.html
 *
 * @package Datametric\LoginShield
 *
 * Datametric Login Shield
 * Copyright (C) 2026 Datametric.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * ---------------------------------------------------------------------------
 * This plugin is a fork of "WPS Hide Login" (GPLv2 or later),
 * Copyright (C) WPServeur, NicolasKulka, wpformation — https://wpserveur.net
 * The original login-interception logic is derived from that project and
 * remains under the GNU General Public License. See readme.txt "Credits".
 * ---------------------------------------------------------------------------
 */

// Don't load directly.
if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

// Plugin constants.
define( 'DLS_VERSION', '1.1.0' );
define( 'DLS_FOLDER', 'datametric-login-shield' );
define( 'DLS_MIN_PHP', '7.2' );

define( 'DLS_FILE', __FILE__ );
define( 'DLS_URL', plugin_dir_url( __FILE__ ) );
define( 'DLS_DIR', plugin_dir_path( __FILE__ ) );
define( 'DLS_BASENAME', plugin_basename( __FILE__ ) );

// Defensive PHP-version guard (the header already blocks activation on old PHP).
if ( version_compare( PHP_VERSION, DLS_MIN_PHP, '<' ) ) {
	return;
}

require_once DLS_DIR . 'src/Autoloader.php';

$dls_autoloader = new \Datametric\LoginShield\Autoloader();
$dls_autoloader->register();
$dls_autoloader->add_namespace( 'Datametric\\LoginShield', DLS_DIR . 'src' );

// Optional Composer autoload (for future third-party libraries).
if ( file_exists( DLS_DIR . 'vendor/autoload.php' ) ) {
	require_once DLS_DIR . 'vendor/autoload.php';
}

register_activation_hook( __FILE__, array( '\Datametric\LoginShield\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( '\Datametric\LoginShield\Plugin', 'deactivate' ) );

add_action( 'plugins_loaded', 'dls_bootstrap_plugin' );

/**
 * Boot the plugin once all plugins are loaded.
 *
 * @return void
 */
function dls_bootstrap_plugin() {
	load_plugin_textdomain(
		'datametric-login-shield',
		false,
		dirname( DLS_BASENAME ) . '/languages'
	);

	\Datametric\LoginShield\Plugin::get_instance();
}
