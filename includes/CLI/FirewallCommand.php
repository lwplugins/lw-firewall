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
				'setting' => 'Protect wp-cron.php',
				'value'   => ! empty( $options['protect_cron'] ) ? 'On' : 'Off',
			],
			[
				'setting' => 'Protect xmlrpc.php',
				'value'   => ! empty( $options['protect_xmlrpc'] ) ? 'On' : 'Off',
			],
			[
				'setting' => 'Protect wp-login.php',
				'value'   => ! empty( $options['protect_login'] ) ? 'On' : 'Off',
			],
			[
				'setting' => 'Protect REST API',
				'value'   => ! empty( $options['protect_rest_api'] ) ? 'On' : 'Off',
			],
			[
				'setting' => 'Protect 404 flood',
				'value'   => ! empty( $options['protect_404'] ) ? 'On' : 'Off',
			],
			[
				'setting' => 'Auto-ban',
				'value'   => ! empty( $options['auto_ban_enabled'] ) ? 'On (' . $options['auto_ban_threshold'] . ' violations / ' . $options['auto_ban_duration'] . 's)' : 'Off',
			],
			[
				'setting' => 'Security headers',
				'value'   => ! empty( $options['security_headers'] ) ? 'On' : 'Off',
			],
			[
				'setting' => 'IP whitelist',
				'value'   => count( (array) ( $options['ip_whitelist'] ?? [] ) ) . ' entries',
			],
			[
				'setting' => 'IP blacklist',
				'value'   => count( (array) ( $options['ip_blacklist'] ?? [] ) ) . ' entries',
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
				'setting' => 'Worker version',
				'value'   => defined( 'LW_FIREWALL_WORKER_VERSION' ) ? LW_FIREWALL_WORKER_VERSION : '—',
			],
			[
				'setting' => 'Blocked bots',
				'value'   => count( (array) ( $options['blocked_bots'] ?? [] ) ) . ' entries',
			],
		];

		Utils\format_items( 'table', $items, [ 'setting', 'value' ] );
	}
}
