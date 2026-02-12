<?php
/**
 * Firewall logs CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\Logger;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * View and manage firewall request logs.
 */
final class LogsCommand {

	/**
	 * List recent log entries.
	 *
	 * ## OPTIONS
	 *
	 * [--limit=<limit>]
	 * : Number of entries to show.
	 * ---
	 * default: 20
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall logs list
	 *     $ wp lw-firewall logs list --limit=50
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 *
	 * @subcommand list
	 */
	public function list_logs( array $args, array $assoc_args ): void {
		$format = Utils\get_flag_value( $assoc_args, 'format', 'table' );
		$limit  = (int) Utils\get_flag_value( $assoc_args, 'limit', 20 );

		$entries = Logger::get_entries();

		if ( empty( $entries ) ) {
			WP_CLI::log( 'No log entries found.' );
			return;
		}

		$entries = array_slice( $entries, 0, $limit );

		// Normalize entries for table display.
		$items = [];
		foreach ( $entries as $entry ) {
			$items[] = [
				'time'   => $entry['time'] ?? '',
				'ip'     => $entry['ip'] ?? '',
				'reason' => $entry['reason'] ?? '',
				'ua'     => $entry['ua'] ?? '',
				'url'    => $entry['url'] ?? '',
			];
		}

		Utils\format_items( $format, $items, [ 'time', 'ip', 'reason', 'ua', 'url' ] );
	}

	/**
	 * Clear all log entries.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Skip confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall logs clear --yes
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function clear( array $args, array $assoc_args ): void {
		WP_CLI::confirm( 'Clear all firewall log entries?', $assoc_args );

		Logger::clear();
		WP_CLI::success( 'Log entries cleared.' );
	}
}
