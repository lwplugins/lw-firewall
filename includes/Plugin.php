<?php
/**
 * Main Plugin class.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

use LightweightPlugins\Firewall\Admin\SettingsPage;
use LightweightPlugins\Firewall\Rules\NotFoundTracker;
use LightweightPlugins\Firewall\Rules\SecurityHeaders;

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
	 * @return void
	 */
	private function init_hooks(): void {
		add_action( 'init', [ $this, 'load_textdomain' ] );

		// Auto-update worker when version mismatch.
		if ( Activator::is_worker_outdated() ) {
			Activator::install_worker();
		}

		$options = Options::get_all();

		if ( ! empty( $options['enabled'] ) ) {
			// 404 flood tracking.
			if ( ! empty( $options['protect_404'] ) ) {
				add_action( 'template_redirect', [ $this, 'track_404' ] );
			}

			// Security headers.
			if ( ! empty( $options['security_headers'] ) ) {
				add_action( 'send_headers', [ SecurityHeaders::class, 'send' ] );
			}
		}
	}

	/**
	 * Track 404 responses for flood detection.
	 *
	 * @return void
	 */
	public function track_404(): void {
		if ( ! is_404() ) {
			return;
		}

		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		$tracker = new NotFoundTracker( $storage );
		$tracker->record();
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
