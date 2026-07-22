<?php
/**
 * Tiny service container.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

/**
 * Minimal service container shared across the free plugin and any Pro add-on.
 *
 * Services can be stored directly or as lazy factories (closures) that are
 * resolved once on first access.
 */
class Container {

	/**
	 * Resolved services.
	 *
	 * @var array<string, mixed>
	 */
	protected $services = array();

	/**
	 * Lazy factories.
	 *
	 * @var array<string, callable>
	 */
	protected $factories = array();

	/**
	 * Register a service or a lazy factory.
	 *
	 * @param string $id    Service identifier.
	 * @param mixed  $value A concrete value, or a callable factory.
	 *
	 * @return void
	 */
	public function set( $id, $value ) {
		if ( is_callable( $value ) ) {
			$this->factories[ $id ] = $value;
			unset( $this->services[ $id ] );
		} else {
			$this->services[ $id ] = $value;
		}
	}

	/**
	 * Whether a service is registered.
	 *
	 * @param string $id Service identifier.
	 *
	 * @return bool
	 */
	public function has( $id ) {
		return isset( $this->services[ $id ] ) || isset( $this->factories[ $id ] );
	}

	/**
	 * Resolve a service.
	 *
	 * @param string $id Service identifier.
	 *
	 * @return mixed|null The service, or null when not registered.
	 */
	public function get( $id ) {
		if ( isset( $this->services[ $id ] ) ) {
			return $this->services[ $id ];
		}

		if ( isset( $this->factories[ $id ] ) ) {
			$this->services[ $id ] = call_user_func( $this->factories[ $id ], $this );

			return $this->services[ $id ];
		}

		return null;
	}
}
