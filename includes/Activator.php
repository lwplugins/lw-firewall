<?php
/**
 * Plugin activation and deactivation.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages MU-plugin worker installation on activate/deactivate.
 */
final class Activator {

	/**
	 * Run on plugin activation.
	 *
	 * Copies the MU-plugin worker into wp-content/mu-plugins/.
	 */
	public static function activate(): void {
		self::install_worker();

		// Save default options if not set yet.
		if ( false === get_option( Options::OPTION_NAME ) ) {
			add_option( Options::OPTION_NAME, Options::get_defaults() );
		}
	}

	/**
	 * Run on plugin deactivation.
	 *
	 * Removes the MU-plugin worker.
	 */
	public static function deactivate(): void {
		self::remove_worker();
		Geo\HtaccessWriter::remove();
	}

	/**
	 * Copy worker file to mu-plugins directory.
	 */
	public static function install_worker(): bool {
		$source = LW_FIREWALL_PATH . 'worker/lw-firewall-worker.php';
		$target = self::get_worker_target_path();

		if ( ! file_exists( $source ) ) {
			return false;
		}

		// Create mu-plugins directory if it doesn't exist.
		$mu_dir = dirname( $target );
		if ( ! is_dir( $mu_dir ) ) {
			wp_mkdir_p( $mu_dir );
		}

		return (bool) copy( $source, $target );
	}

	/**
	 * Remove worker file from mu-plugins directory.
	 */
	public static function remove_worker(): bool {
		$target = self::get_worker_target_path();

		if ( file_exists( $target ) ) {
			wp_delete_file( $target );
			return ! file_exists( $target );
		}

		return true;
	}

	/**
	 * Check if the worker is installed.
	 */
	public static function is_worker_installed(): bool {
		return file_exists( self::get_worker_target_path() );
	}

	/**
	 * Check if the installed worker is outdated.
	 */
	public static function is_worker_outdated(): bool {
		if ( ! self::is_worker_installed() ) {
			return true;
		}

		return ! defined( 'LW_FIREWALL_WORKER_VERSION' )
			|| LW_FIREWALL_WORKER_VERSION !== LW_FIREWALL_VERSION;
	}

	/**
	 * Get the target path for the MU-plugin worker.
	 */
	private static function get_worker_target_path(): string {
		return WPMU_PLUGIN_DIR . '/lw-firewall-worker.php';
	}
}
