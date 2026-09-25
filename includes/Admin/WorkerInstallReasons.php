<?php
/**
 * Human-readable worker install outcomes.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Maps the machine codes Activator::install_worker() records to sentences,
 * so no screen or API response ever shows a raw code like
 * `mu_dir_not_writable`.
 */
final class WorkerInstallReasons {

	/**
	 * Every known failure code => sentence.
	 *
	 * @return array<string, string>
	 */
	public static function all(): array {
		return [
			'source_missing'       => __( 'The worker source file inside the plugin is missing.', 'lw-firewall' ),
			'mu_dir_create_failed' => __( 'The mu-plugins directory could not be created.', 'lw-firewall' ),
			'mu_dir_not_writable'  => __( 'The mu-plugins directory is not writable.', 'lw-firewall' ),
			'copy_failed'          => __( 'Copying the worker file failed (disk full or permission denied).', 'lw-firewall' ),
		];
	}

	/**
	 * The sentence for one failure code.
	 *
	 * @param string $code Failure code.
	 * @return string
	 */
	public static function message( string $code ): string {
		return self::all()[ $code ] ?? __( 'Unknown install error.', 'lw-firewall' );
	}
}
