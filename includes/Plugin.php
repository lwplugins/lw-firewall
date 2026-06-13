<?php
/**
 * Main Plugin class.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

use LightweightPlugins\Firewall\Admin\SettingsPage;
use LightweightPlugins\Firewall\Admin\WorkerNotice;
use LightweightPlugins\Firewall\Geo\CidrUpdater;
use LightweightPlugins\Firewall\Rules\LoginTracker;
use LightweightPlugins\Firewall\Rules\NotFoundTracker;
use LightweightPlugins\Firewall\Rules\RegisterGuard;
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
		$this->bootstrap_worker();
		$this->init_admin();
		$this->init_site_manager();
	}

	/**
	 * Bootstrap the MU-plugin worker, then either start the runtime or halt.
	 *
	 * If the worker file is missing or out of date we self-heal once. If the
	 * heal fails the plugin refuses to register its runtime hooks and shows
	 * an admin notice — better to be visibly broken than silently half-on.
	 *
	 * @return void
	 */
	private function bootstrap_worker(): void {
		add_action( 'init', [ $this, 'load_textdomain' ] );
		add_action( 'upgrader_process_complete', [ $this, 'reinstall_after_upgrade' ], 10, 2 );

		if ( Activator::is_worker_outdated() ) {
			Activator::install_worker();
		}

		if ( Activator::is_worker_outdated() ) {
			add_action( 'admin_notices', [ WorkerNotice::class, 'render' ] );
			add_action( 'network_admin_notices', [ WorkerNotice::class, 'render' ] );
			return;
		}

		$this->init_runtime_hooks();
	}

	/**
	 * Initialize hooks that depend on a healthy worker.
	 *
	 * @return void
	 */
	private function init_runtime_hooks(): void {
		$options = Options::get_all();

		if ( empty( $options['enabled'] ) ) {
			return;
		}

		// 404 flood tracking.
		if ( ! empty( $options['protect_404'] ) ) {
			add_action( 'template_redirect', [ $this, 'track_404' ] );
		}

		// Brute-force login protection.
		if ( ! empty( $options['login_limit_enabled'] ) ) {
			add_action( 'wp_login_failed', [ $this, 'track_failed_login' ] );
		}

		// Registration spam protection (default WP register form only).
		if ( ! empty( $options['register_protect_enabled'] ) && get_option( 'users_can_register' ) ) {
			add_action( 'register_form', [ RegisterGuard::class, 'render_fields' ] );
			add_filter( 'registration_errors', [ RegisterGuard::class, 'validate' ], 10, 3 );
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
		( new NotFoundTracker( $storage ) )->record();
	}

	/**
	 * Record a failed login attempt for brute-force protection (hook callback).
	 *
	 * @return void
	 */
	public function track_failed_login(): void {
		LoginTracker::handle();
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
	 * Reinstall the worker right after a plugin self-update.
	 *
	 * Without this, the old worker keeps running against new class files
	 * until the next page load triggers init_hooks reinstall — too late if
	 * the API surface changed in the same release.
	 *
	 * @param mixed                $upgrader   Upgrader instance (unused).
	 * @param array<string, mixed> $hook_extra Hook context.
	 * @return void
	 */
	public function reinstall_after_upgrade( $upgrader, array $hook_extra ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		if ( ( $hook_extra['type'] ?? '' ) !== 'plugin' ) {
			return;
		}

		$plugins = (array) ( $hook_extra['plugins'] ?? [] );

		// Bail unless this update touched lw-firewall (or context is unknown).
		if ( ! empty( $plugins ) ) {
			$matched = false;
			foreach ( $plugins as $plugin_file ) {
				if ( str_contains( (string) $plugin_file, 'lw-firewall' ) ) {
					$matched = true;
					break;
				}
			}
			if ( ! $matched ) {
				return;
			}
		}

		Activator::install_worker();
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
