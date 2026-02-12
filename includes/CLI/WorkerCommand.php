<?php
/**
 * Firewall worker CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\Activator;
use WP_CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage the MU-plugin worker.
 */
final class WorkerCommand {

	/**
	 * Install or reinstall the MU-plugin worker.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall worker install
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function install( array $args, array $assoc_args ): void {
		if ( Activator::install_worker() ) {
			WP_CLI::success( 'MU-plugin worker installed.' );
		} else {
			WP_CLI::error( 'Failed to install MU-plugin worker.' );
		}
	}

	/**
	 * Remove the MU-plugin worker.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall worker remove
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function remove( array $args, array $assoc_args ): void {
		if ( ! Activator::is_worker_installed() ) {
			WP_CLI::warning( 'Worker is not installed.' );
			return;
		}

		if ( Activator::remove_worker() ) {
			WP_CLI::success( 'MU-plugin worker removed.' );
		} else {
			WP_CLI::error( 'Failed to remove MU-plugin worker.' );
		}
	}
}
