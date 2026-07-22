<?php
/**
 * Plugin Name:       Datametric Login Shield
 * Plugin URI:        https://www.datametric.com.tr/login-shield
 * Description:        Hide your WordPress login URL and block access to wp-login.php and the wp-admin directory for logged-out visitors. Modular login-security layer by Datametric.
 * Version:           1.1.0
 * Author:            Datametric
 * Author URI:        https://www.datametric.com.tr
 * Requires at least: 5.3
 * Tested up to:      7.0
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
define( 'DMLS_VERSION', '1.1.0' );
define( 'DMLS_FOLDER', 'datametric-login-shield' );
define( 'DMLS_MIN_PHP', '7.2' );

define( 'DMLS_FILE', __FILE__ );
define( 'DMLS_URL', plugin_dir_url( __FILE__ ) );
define( 'DMLS_DIR', plugin_dir_path( __FILE__ ) );
define( 'DMLS_BASENAME', plugin_basename( __FILE__ ) );

// Defensive PHP-version guard (the header already blocks activation on old PHP).
if ( version_compare( PHP_VERSION, DMLS_MIN_PHP, '<' ) ) {
	return;
}

require_once DMLS_DIR . 'src/Autoloader.php';

$dmls_autoloader = new \Datametric\LoginShield\Autoloader();
$dmls_autoloader->register();
$dmls_autoloader->add_namespace( 'Datametric\\LoginShield', DMLS_DIR . 'src' );

// Optional Composer autoload (for future third-party libraries).
if ( file_exists( DMLS_DIR . 'vendor/autoload.php' ) ) {
	require_once DMLS_DIR . 'vendor/autoload.php';
}

register_activation_hook( __FILE__, array( '\Datametric\LoginShield\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( '\Datametric\LoginShield\Plugin', 'deactivate' ) );

add_action( 'plugins_loaded', 'dmls_bootstrap_plugin' );

/**
 * Boot the plugin once all plugins are loaded.
 *
 * @return void
 */
function dmls_bootstrap_plugin() {
	// Translations load automatically (WP 4.6+); no load_plugin_textdomain() needed.
	\Datametric\LoginShield\Plugin::get_instance();
}
