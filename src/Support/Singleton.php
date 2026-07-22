<?php
/**
 * Singleton trait.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

/**
 * Provides a single-instance implementation for the using class.
 */
trait Singleton {

	/**
	 * The single instance.
	 *
	 * @var self
	 */
	protected static $instance;

	/**
	 * Retrieve the single instance.
	 *
	 * @return static
	 */
	final public static function get_instance() {
		if ( is_null( static::$instance ) ) {
			static::$instance = new static();
		}

		return static::$instance;
	}

	/**
	 * Protected constructor; runs init().
	 */
	private function __construct() {
		$this->init();
	}

	/**
	 * Override in the using class to wire up behaviour.
	 *
	 * @return void
	 */
	protected function init() {}

	/**
	 * Prevent cloning.
	 *
	 * @return void
	 */
	final public function __clone() {}

	/**
	 * Prevent unserialization.
	 *
	 * @return void
	 */
	final public function __wakeup() {}
}
