<?php
/**
 * Firewall bots CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

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
		$ua   = $args[0];
		$bots = (array) Options::get( 'blocked_bots', [] );

		// Check for duplicates (case-insensitive).
		$ua_lower = strtolower( $ua );
		foreach ( $bots as $existing ) {
			if ( strtolower( (string) $existing ) === $ua_lower ) {
				WP_CLI::error( "'{$ua}' is already in the block list." );
			}
		}

		$bots[]                  = $ua;
		$current                 = Options::get_all();
		$current['blocked_bots'] = $bots;

		if ( Options::save( $current ) ) {
			WP_CLI::success( "Added '{$ua}' to the blocked bots list." );
		} else {
			WP_CLI::error( 'Failed to update blocked bots list.' );
		}
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
		$ua   = $args[0];
		$bots = (array) Options::get( 'blocked_bots', [] );

		$ua_lower = strtolower( $ua );
		$found    = false;

		$bots = array_values(
			array_filter(
				$bots,
				static function ( $existing ) use ( $ua_lower, &$found ): bool {
					if ( strtolower( (string) $existing ) === $ua_lower ) {
						$found = true;
						return false;
					}
					return true;
				}
			)
		);

		if ( ! $found ) {
			WP_CLI::error( "'{$ua}' was not found in the block list." );
		}

		$current                 = Options::get_all();
		$current['blocked_bots'] = $bots;

		if ( Options::save( $current ) ) {
			WP_CLI::success( "Removed '{$ua}' from the blocked bots list." );
		} else {
			WP_CLI::error( 'Failed to update blocked bots list.' );
		}
	}
}
