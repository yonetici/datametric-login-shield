<?php
/**
 * Module contract.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield\Contracts;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use Datametric\LoginShield\Container;

/**
 * A feature module.
 *
 * The free plugin ships core modules; a Pro add-on registers additional
 * modules through the `dls_register_modules` filter. Each module wires its
 * services in register() and adds its WordPress hooks in boot().
 */
interface ModuleInterface {

	/**
	 * Unique module identifier (e.g. "hide-login").
	 *
	 * @return string
	 */
	public function id();

	/**
	 * Wire services into the container. Runs before boot() for every module,
	 * so a module may rely on services registered by another.
	 *
	 * @param Container $container Shared container.
	 *
	 * @return void
	 */
	public function register( Container $container );

	/**
	 * Add WordPress hooks / start doing work.
	 *
	 * @return void
	 */
	public function boot();

	/**
	 * Whether this module belongs to the Pro add-on.
	 *
	 * @return bool
	 */
	public function is_pro();
}
