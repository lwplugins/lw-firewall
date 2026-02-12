<?php
/**
 * Firewall main CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\Activator;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageDetector;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * LW Firewall — WooCommerce filter rate limiter.
 */
final class FirewallCommand {

	/**
	 * Show firewall status overview.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall status
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 *
	 * @subcommand status
	 */
	public function status( array $args, array $assoc_args ): void {
		$options      = Options::get_all();
		$storage_pref = (string) ( $options['storage'] ?? 'auto' );

		$items = [
			[
				'setting' => 'Enabled',
				'value'   => ! empty( $options['enabled'] ) ? 'Yes' : 'No',
			],
			[
				'setting' => 'Storage (preference)',
				'value'   => $storage_pref,
			],
			[
				'setting' => 'Storage (active)',
				'value'   => StorageDetector::detect( $storage_pref ),
			],
			[
				'setting' => 'Rate limit',
				'value'   => $options['rate_limit'] . ' req / ' . $options['rate_window'] . 's',
			],
			[
				'setting' => 'Action',
				'value'   => $options['action'],
			],
			[
				'setting' => 'Logging',
				'value'   => ! empty( $options['log_enabled'] ) ? 'On' : 'Off',
			],
			[
				'setting' => 'MU-Plugin worker',
				'value'   => Activator::is_worker_installed() ? 'Installed' : 'Not installed',
			],
			[
				'setting' => 'Blocked bots',
				'value'   => count( (array) ( $options['blocked_bots'] ?? [] ) ) . ' entries',
			],
		];

		Utils\format_items( 'table', $items, [ 'setting', 'value' ] );
	}
}
