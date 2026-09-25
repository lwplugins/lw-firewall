<?php
/**
 * Firewall bots CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\CLI\Support\ConfigOpsTrait;
use LightweightPlugins\Firewall\Options;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage blocked bot User-Agents.
 */
final class BotsCommand {

	use ConfigOpsTrait;

	/**
	 * List blocked bot User-Agent strings.
	 *
	 * ## OPTIONS
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
	 *     $ wp lw-firewall bots list
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 *
	 * @subcommand list
	 */
	public function list_bots( array $args, array $assoc_args ): void {
		$format = Utils\get_flag_value( $assoc_args, 'format', 'table' );
		$bots   = (array) Options::get( 'blocked_bots', [] );

		if ( empty( $bots ) ) {
			WP_CLI::log( 'No blocked bots configured.' );
			return;
		}

		$items = [];
		foreach ( $bots as $i => $ua ) {
			$items[] = [
				'#'          => $i + 1,
				'user_agent' => $ua,
			];
		}

		Utils\format_items( $format, $items, [ '#', 'user_agent' ] );
	}

	/**
	 * Add a bot User-Agent to the block list.
	 *
	 * ## OPTIONS
	 *
	 * <user_agent>
	 * : The User-Agent string to block (case-insensitive substring match).
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall bots add "newbot/1.0"
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function add( array $args, array $assoc_args ): void {
		$ua   = trim( (string) $args[0] );
		$bots = self::resolve_list_or_fail( 'blocked_bots' );

		// Check for duplicates (case-insensitive).
		$ua_lower = strtolower( $ua );
		foreach ( $bots as $existing ) {
			if ( strtolower( $existing ) === $ua_lower ) {
				WP_CLI::error( "'{$ua}' is already in the block list." );
			}
		}

		$bots[] = $ua;
		self::save_list( 'blocked_bots', $bots );

		WP_CLI::success( "Added '{$ua}' to the blocked bots list." );
	}

	/**
	 * Remove a bot User-Agent from the block list.
	 *
	 * ## OPTIONS
	 *
	 * <user_agent>
	 * : The User-Agent string to remove (case-insensitive match).
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall bots remove "newbot/1.0"
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function remove( array $args, array $assoc_args ): void {
		$ua_lower  = strtolower( trim( (string) $args[0] ) );
		$bots      = self::resolve_list_or_fail( 'blocked_bots' );
		$remaining = array_values( array_filter( $bots, static fn ( string $existing ): bool => strtolower( $existing ) !== $ua_lower ) );

		if ( count( $remaining ) === count( $bots ) ) {
			WP_CLI::error( "'{$args[0]}' was not found in the block list." );
		}

		self::save_list( 'blocked_bots', $remaining );

		WP_CLI::success( "Removed '{$args[0]}' from the blocked bots list." );
	}
}
