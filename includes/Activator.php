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
	 * Transient key storing the last install attempt status.
	 */
	public const ATTEMPT_TRANSIENT = 'lw_firewall_worker_install_attempt';

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

		Geo\HtaccessWriter::sync();
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
	 *
	 * Records the attempt outcome in a transient so the admin UI / notices
	 * can show actionable feedback when permissions, disk space, or a
	 * security plugin keep the worker from sticking.
	 */
	public static function install_worker(): bool {
		$source = LW_FIREWALL_PATH . 'worker/lw-firewall-worker.php';
		$target = self::get_worker_target_path();
		$mu_dir = dirname( $target );

		if ( ! file_exists( $source ) ) {
			self::record_attempt( false, 'source_missing' );
			return false;
		}

		if ( ! is_dir( $mu_dir ) && ! wp_mkdir_p( $mu_dir ) ) {
			self::record_attempt( false, 'mu_dir_create_failed' );
			return false;
		}

		if ( ! wp_is_writable( $mu_dir ) ) {
			self::record_attempt( false, 'mu_dir_not_writable' );
			return false;
		}

		$copied = @copy( $source, $target ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( ! $copied || ! file_exists( $target ) ) {
			self::record_attempt( false, 'copy_failed' );
			return false;
		}

		self::record_attempt( true, '' );
		return true;
	}

	/**
	 * Remove worker file from mu-plugins directory.
	 */
	public static function remove_worker(): bool {
		$target = self::get_worker_target_path();

		if ( file_exists( $target ) ) {
			wp_delete_file( $target );
			// file_exists() is re-evaluated at runtime after the delete; PHPStan
			// cannot model wp_delete_file()'s filesystem side effect.
			// @phpstan-ignore booleanNot.alwaysFalse
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

		if ( ! defined( 'LW_FIREWALL_WORKER_VERSION' ) ) {
			return true;
		}

		// The two constants are defined in separate files — the installed
		// MU-worker vs the current plugin — and legitimately differ at runtime
		// after an update. Static analysis sees only one build, so it reads them
		// as identical.
		// @phpstan-ignore notIdentical.alwaysFalse
		return LW_FIREWALL_WORKER_VERSION !== LW_FIREWALL_VERSION;
	}

	/**
	 * Check if the mu-plugins directory is writable.
	 */
	public static function is_mu_dir_writable(): bool {
		$mu_dir = dirname( self::get_worker_target_path() );

		if ( ! is_dir( $mu_dir ) ) {
			return wp_is_writable( dirname( $mu_dir ) );
		}

		return wp_is_writable( $mu_dir );
	}

	/**
	 * Get the last install attempt info (timestamp + result).
	 *
	 * @return array{success: bool, error: string, time: int}|null
	 */
	public static function get_last_attempt(): ?array {
		$data = get_transient( self::ATTEMPT_TRANSIENT );

		return is_array( $data ) ? $data : null;
	}

	/**
	 * Get the target path for the MU-plugin worker.
	 */
	private static function get_worker_target_path(): string {
		return WPMU_PLUGIN_DIR . '/lw-firewall-worker.php';
	}

	/**
	 * Persist the most recent install attempt outcome.
	 *
	 * @param bool   $success Whether the copy succeeded.
	 * @param string $error   Short machine-readable error code.
	 */
	private static function record_attempt( bool $success, string $error ): void {
		set_transient(
			self::ATTEMPT_TRANSIENT,
			[
				'success' => $success,
				'error'   => $error,
				'time'    => time(),
			],
			DAY_IN_SECONDS
		);
	}
}
