<?php
/**
 * Plugin bootstrap: container + module registry.
 *
 * @package Datametric\LoginShield
 */

namespace Datametric\LoginShield;

if ( ! defined( 'ABSPATH' ) ) {
	die( '-1' );
}

use Datametric\LoginShield\Support\Singleton;
use Datametric\LoginShield\Support\Options;
use Datametric\LoginShield\Support\Database;
use Datametric\LoginShield\Contracts\ModuleInterface;
use Datametric\LoginShield\Modules\HideLogin\HideLoginModule;
use Datametric\LoginShield\Modules\BruteForce\BruteForceModule;
use Datametric\LoginShield\Modules\Hardening\HardeningModule;
use Datametric\LoginShield\Modules\AuditLog\AuditLogModule;
use Datametric\LoginShield\Admin\SettingsPage;

/**
 * Main plugin controller.
 *
 * Collects feature modules (core + anything a Pro add-on adds via the
 * `dmls_register_modules` filter), wires their services, then boots them.
 */
class Plugin {

	use Singleton;

	/**
	 * Shared service container.
	 *
	 * @var Container
	 */
	protected $container;

	/**
	 * Booted modules, keyed by id.
	 *
	 * @var ModuleInterface[]
	 */
	protected $modules = array();

	/**
	 * Admin settings screen (admin requests only).
	 *
	 * @var SettingsPage|null
	 */
	protected $admin;

	/**
	 * Wire everything up.
	 *
	 * @return void
	 */
	protected function init() {
		$this->container = new Container();
		$this->container->set( 'plugin', $this );

		// Keep the schema current and make sure maintenance is scheduled.
		Database::maybe_upgrade();
		if ( ! wp_next_scheduled( 'dmls_daily_maintenance' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'dmls_daily_maintenance' );
		}

		if ( is_admin() ) {
			$this->admin = new SettingsPage();
			$this->container->set( 'admin', $this->admin );
		}

		/**
		 * Filter the list of modules to load.
		 *
		 * A Pro add-on appends its own ModuleInterface instances here.
		 *
		 * @param ModuleInterface[] $modules   Core modules.
		 * @param Container         $container Shared container.
		 */
		$modules = apply_filters( 'dmls_register_modules', $this->core_modules(), $this->container );

		foreach ( (array) $modules as $module ) {
			if ( $module instanceof ModuleInterface ) {
				$this->modules[ $module->id() ] = $module;
			}
		}

		foreach ( $this->modules as $module ) {
			$module->register( $this->container );
		}

		foreach ( $this->modules as $module ) {
			$module->boot();
		}

		if ( $this->admin ) {
			$this->admin->boot();
		}

		/**
		 * Fires once all core modules are booted. Pro add-ons hook here to
		 * confirm the free plugin is present and grab the container.
		 *
		 * @param Container $container Shared container.
		 */
		do_action( 'dmls_loaded', $this->container );
	}

	/**
	 * Core (free) modules shipped with the plugin.
	 *
	 * @return ModuleInterface[]
	 */
	protected function core_modules() {
		return array(
			new HideLoginModule(),
			new BruteForceModule(),
			new HardeningModule(),
			new AuditLogModule(),
		);
	}

	/**
	 * Access the shared container.
	 *
	 * @return Container
	 */
	public function container() {
		return $this->container;
	}

	/**
	 * Fetch a booted module by id.
	 *
	 * @param string $id Module id.
	 *
	 * @return ModuleInterface|null
	 */
	public function module( $id ) {
		return isset( $this->modules[ $id ] ) ? $this->modules[ $id ] : null;
	}

	/**
	 * Activation: migrate legacy settings and flush rewrite rules.
	 *
	 * @return void
	 */
	public static function activate() {
		Options::maybe_migrate_legacy();
		Database::install_all();

		if ( ! wp_next_scheduled( 'dmls_daily_maintenance' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'dmls_daily_maintenance' );
		}

		/**
		 * Fires on plugin activation (before rewrite flush).
		 */
		do_action( 'dmls_activate' );

		flush_rewrite_rules();
	}

	/**
	 * Deactivation: restore default routing.
	 *
	 * @return void
	 */
	public static function deactivate() {
		if ( is_multisite() ) {
			$site_ids = get_sites(
				array(
					'fields' => 'ids',
					'number' => 0,
				)
			);
			foreach ( (array) $site_ids as $site_id ) {
				switch_to_blog( $site_id );
				self::unschedule_maintenance();
				restore_current_blog();
			}
		} else {
			self::unschedule_maintenance();
		}

		/**
		 * Fires on plugin deactivation.
		 */
		do_action( 'dmls_deactivate' );

		flush_rewrite_rules();
	}

	/**
	 * Unschedule the maintenance cron for the current site.
	 *
	 * @return void
	 */
	private static function unschedule_maintenance() {
		$timestamp = wp_next_scheduled( 'dmls_daily_maintenance' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'dmls_daily_maintenance' );
		}
	}
}
