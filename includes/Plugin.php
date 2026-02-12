<?php
/**
 * Main Plugin class.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

use LightweightPlugins\Firewall\Admin\SettingsPage;

/**
 * Main plugin class.
 */
final class Plugin {

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->init_hooks();
		$this->init_admin();
	}

	/**
	 * Initialize hooks.
	 *
	 * Protection runs via the MU-plugin worker, not here.
	 *
	 * @return void
	 */
	private function init_hooks(): void {
		add_action( 'init', [ $this, 'load_textdomain' ] );
	}

	/**
	 * Initialize admin components.
	 *
	 * @return void
	 */
	private function init_admin(): void {
		if ( is_admin() ) {
			new SettingsPage();
		}
	}

	/**
	 * Load plugin textdomain.
	 *
	 * @return void
	 */
	public function load_textdomain(): void {
		load_plugin_textdomain(
			'lw-firewall',
			false,
			dirname( plugin_basename( LW_FIREWALL_FILE ) ) . '/languages'
		);
	}
}
