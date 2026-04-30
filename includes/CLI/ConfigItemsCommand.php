<?php
/**
 * Firewall config-items CLI command — append / remove single entries on
 * list-typed options.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\CLI\Support\ConfigOpsTrait;
use WP_CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Edit list-typed firewall settings (filter_params, blocked_bots,
 * ip_whitelist, ip_blacklist, blocked_countries) one entry at a time.
 *
 * Use `wp lw-firewall config get <key>` to see the current list, and
 * `wp lw-firewall config set <key> "..."` to replace the whole list.
 */
final class ConfigItemsCommand {

	use ConfigOpsTrait;

	/**
	 * Append an entry to a list option.
	 *
	 * Duplicates are skipped with a warning.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The list-typed setting key.
	 *
	 * <entry>
	 * : The entry to append.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall config-items add filter_params "add-to-cart|10"
	 *     $ wp lw-firewall config-items add blocked_countries KP
	 *     $ wp lw-firewall config-items add ip_blacklist 203.0.113.42
	 *
	 * @param array<int, string>   $args       Positional arguments.
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 */
	public function add( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		[ $key, $entry ] = $args;
		$entry           = trim( (string) $entry );

		if ( '' === $entry ) {
			WP_CLI::error( 'Cannot add an empty entry.' );
		}

		$list = self::resolve_list_or_fail( $key );

		if ( in_array( $entry, $list, true ) ) {
			WP_CLI::warning( "Entry '{$entry}' already in '{$key}'." );
			return;
		}

		$list[] = $entry;
		self::save_list( $key, $list );

		WP_CLI::success( sprintf( "Added '%s' to '%s' (%d entries).", $entry, $key, count( $list ) ) );
	}

	/**
	 * Remove an entry from a list option (exact match).
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The list-typed setting key.
	 *
	 * <entry>
	 * : The entry to remove.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall config-items remove filter_params "add-to-cart|10"
	 *     $ wp lw-firewall config-items remove blocked_countries KP
	 *
	 * @param array<int, string>   $args       Positional arguments.
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 */
	public function remove( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		[ $key, $entry ] = $args;

		$list = self::resolve_list_or_fail( $key );
		$idx  = array_search( $entry, $list, true );

		if ( false === $idx ) {
			WP_CLI::warning( "Entry '{$entry}' not found in '{$key}'." );
			return;
		}

		array_splice( $list, (int) $idx, 1 );
		self::save_list( $key, $list );

		WP_CLI::success( sprintf( "Removed '%s' from '%s' (%d entries).", $entry, $key, count( $list ) ) );
	}
}
