<?php
/**
 * The MU-plugin worker's state.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Status;

use LightweightPlugins\Firewall\Activator;
use LightweightPlugins\Firewall\Admin\WorkerInstallReasons;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Installed, version match, heartbeat age and the last install attempt with
 * its failure code mapped to a sentence.
 */
final class WorkerState {

	/**
	 * Build the worker block.
	 *
	 * @return array<string, mixed>
	 */
	public static function build(): array {
		$version   = defined( 'LW_FIREWALL_WORKER_VERSION' ) ? (string) LW_FIREWALL_WORKER_VERSION : null;
		$last_seen = Activator::worker_last_seen();

		return [
			'installed'       => Activator::is_worker_installed(),
			'version'         => $version,
			'expected'        => LW_FIREWALL_VERSION,
			'version_match'   => LW_FIREWALL_VERSION === $version,
			'outdated'        => Activator::is_worker_outdated(),
			'kill_switch'     => defined( 'LW_FIREWALL_DISABLE_WORKER' ) && LW_FIREWALL_DISABLE_WORKER,
			'mu_dir'          => defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '',
			'mu_dir_writable' => Activator::is_mu_dir_writable(),
			'last_seen'       => $last_seen,
			'heartbeat_age'   => $last_seen > 0 ? max( 0, time() - $last_seen ) : null,
			'last_attempt'    => self::attempt( Activator::get_last_attempt(), time() ),
		];
	}

	/**
	 * The last install attempt, with a sentence instead of a raw code.
	 *
	 * @param array<string, mixed>|null $attempt Stored attempt (a transient, so its shape is not guaranteed).
	 * @param int                       $now     Current UNIX timestamp.
	 * @return array{success: bool, code: string, message: string, time: int, age: int}|null
	 */
	public static function attempt( ?array $attempt, int $now ): ?array {
		if ( null === $attempt ) {
			return null;
		}

		$success = ! empty( $attempt['success'] );
		$code    = (string) ( $attempt['error'] ?? '' );
		$time    = (int) ( $attempt['time'] ?? 0 );

		return [
			'success' => $success,
			'code'    => $code,
			'message' => $success ? __( 'The worker was installed.', 'lw-firewall' ) : WorkerInstallReasons::message( $code ),
			'time'    => $time,
			'age'     => max( 0, $now - $time ),
		];
	}
}
