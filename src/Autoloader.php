<?php
/**
 * PSR-4 autoloader.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

/**
 * Minimal PSR-4 autoloader for the Datametric\LoginShield namespace.
 *
 * File names follow the class name exactly: class Foo_Bar -> Foo_Bar.php,
 * class SettingsPage -> SettingsPage.php. Sub-namespaces map to sub-folders.
 */
class Autoloader {

	/**
	 * Map of namespace prefix => list of base directories.
	 *
	 * @var array<string, string[]>
	 */
	protected $prefixes = array();

	/**
	 * Register the autoloader with the SPL stack.
	 *
	 * @return void
	 */
	public function register() {
		spl_autoload_register( array( $this, 'load_class' ) );
	}

	/**
	 * Add a base directory for a namespace prefix.
	 *
	 * @param string $prefix   Namespace prefix.
	 * @param string $base_dir Base directory for class files in the namespace.
	 * @param bool   $prepend  Whether to prepend (search first).
	 *
	 * @return void
	 */
	public function add_namespace( $prefix, $base_dir, $prepend = false ) {
		$prefix   = trim( $prefix, '\\' ) . '\\';
		$base_dir = rtrim( $base_dir, DIRECTORY_SEPARATOR ) . '/';

		if ( ! isset( $this->prefixes[ $prefix ] ) ) {
			$this->prefixes[ $prefix ] = array();
		}

		if ( $prepend ) {
			array_unshift( $this->prefixes[ $prefix ], $base_dir );
		} else {
			$this->prefixes[ $prefix ][] = $base_dir;
		}
	}

	/**
	 * Load the file for a fully-qualified class name.
	 *
	 * @param string $class Fully-qualified class name.
	 *
	 * @return string|false The mapped file on success, false otherwise.
	 */
	public function load_class( $class ) {
		$prefix = $class;

		while ( false !== $pos = strrpos( $prefix, '\\' ) ) {
			$prefix         = substr( $class, 0, $pos + 1 );
			$relative_class = substr( $class, $pos + 1 );

			$mapped_file = $this->load_mapped_file( $prefix, $relative_class );
			if ( $mapped_file ) {
				return $mapped_file;
			}

			$prefix = rtrim( $prefix, '\\' );
		}

		return false;
	}

	/**
	 * Load the mapped file for a namespace prefix and relative class.
	 *
	 * @param string $prefix         Namespace prefix.
	 * @param string $relative_class Relative class name.
	 *
	 * @return string|false The mapped file on success, false otherwise.
	 */
	protected function load_mapped_file( $prefix, $relative_class ) {
		if ( ! isset( $this->prefixes[ $prefix ] ) ) {
			return false;
		}

		foreach ( $this->prefixes[ $prefix ] as $base_dir ) {
			$file = $base_dir . str_replace( '\\', '/', $relative_class ) . '.php';

			if ( $this->require_file( $file ) ) {
				return $file;
			}
		}

		return false;
	}

	/**
	 * Require a file if it exists.
	 *
	 * @param string $file File path.
	 *
	 * @return bool True if required, false otherwise.
	 */
	protected function require_file( $file ) {
		if ( file_exists( $file ) ) {
			require_once $file;

			return true;
		}

		return false;
	}
}
