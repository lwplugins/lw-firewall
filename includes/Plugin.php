<?php
/**
 * Main Plugin class.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

use LightweightPlugins\Firewall\Admin\SettingsPage;
use LightweightPlugins\Firewall\Geo\CidrUpdater;
use LightweightPlugins\Firewall\Rules\NotFoundTracker;
use LightweightPlugins\Firewall\Rules\SecurityHeaders;
use LightweightPlugins\Firewall\SiteManager\Integration as SiteManagerIntegration;

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
		$this->init_site_manager();
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
			if ( ! Activator::install_worker() ) {
				add_action( 'admin_notices', [ $this, 'worker_install_notice' ] );
			}
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

			// Geo blocking CIDR updater cron.
			if ( ! empty( $options['geo_enabled'] ) ) {
				add_action( CidrUpdater::CRON_HOOK, [ $this, 'update_geo_cidrs' ] );

				if ( ! wp_next_scheduled( CidrUpdater::CRON_HOOK ) ) {
					wp_schedule_event( time(), 'weekly', CidrUpdater::CRON_HOOK );
				}
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
	 * Update CIDR lists for blocked countries (cron callback).
	 *
	 * @return void
	 */
	public function update_geo_cidrs(): void {
		$countries = (array) Options::get( 'blocked_countries', [] );

		if ( ! empty( $countries ) ) {
			CidrUpdater::update( $countries );
		}
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
	 * Initialize LW Site Manager integration.
	 *
	 * @return void
	 */
	private function init_site_manager(): void {
		SiteManagerIntegration::init();
	}

	/**
	 * Show admin notice when worker installation fails.
	 *
	 * @return void
	 */
	public function worker_install_notice(): void {
		$mu_dir = WPMU_PLUGIN_DIR;
		?>
		<div class="notice notice-error">
			<p>
				<strong>LW Firewall:</strong>
				<?php
				printf(
					/* translators: %s: mu-plugins directory path */
					esc_html__( 'Could not install the MU-plugin worker. Please ensure %s is writable.', 'lw-firewall' ),
					'<code>' . esc_html( $mu_dir ) . '</code>'
				);
				?>
			</p>
		</div>
		<?php
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
