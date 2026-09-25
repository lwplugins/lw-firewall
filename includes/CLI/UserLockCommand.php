<?php
/**
 * Username lock CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\Admin\Bans\UserUnlocker;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rules\UserLockList;
use LightweightPlugins\Firewall\Rules\UserLockout;
use LightweightPlugins\Firewall\Storage\StorageInterface;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * List and lift per-username login locks.
 */
final class UserLockCommand {

	/**
	 * List locked usernames.
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
	 *     $ wp lw-firewall user-lock list
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 *
	 * @subcommand list
	 */
	public function list_locks( array $args, array $assoc_args ): void {
		$rows = UserLockList::all( self::storage() );

		if ( [] === $rows ) {
			WP_CLI::log( 'No locked usernames.' );
			return;
		}

		$items = [];

		foreach ( $rows as $row ) {
			$items[] = [
				'user'    => $row['user'],
				'key'     => $row['key'],
				'expires' => gmdate( 'Y-m-d H:i:s', $row['expires'] ) . ' UTC',
				'active'  => $row['active'] ? 'yes' : 'no',
			];
		}

		Utils\format_items( (string) Utils\get_flag_value( $assoc_args, 'format', 'table' ), $items, [ 'user', 'key', 'expires', 'active' ] );
	}

	/**
	 * Unlock one username (or lock key from `list`).
	 *
	 * ## OPTIONS
	 *
	 * <username>
	 * : The username as typed at login, or its key.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall user-lock remove admin
	 *
	 * @param array<int, string>   $args       Positional arguments.
	 * @param array<string, mixed> $assoc_args Associative arguments (unused).
	 */
	public function remove( array $args, array $assoc_args ): void {
		$result = ( new UserUnlocker( new UserLockout( self::storage() ) ) )->unlock( [ $args[0] ] )[0];

		if ( ! $result['ok'] ) {
			WP_CLI::error( $result['message'] );
		}

		WP_CLI::success( sprintf( "Unlocked '%s'.", $result['user'] ) );
	}

	/**
	 * Unlock every locked username.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall user-lock clear
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments (unused).
	 */
	public function clear( array $args, array $assoc_args ): void {
		$results = ( new UserUnlocker( new UserLockout( self::storage() ) ) )->unlock_all();
		$failed  = array_filter( $results, static fn ( array $r ): bool => ! $r['ok'] );

		if ( [] !== $failed ) {
			WP_CLI::error( sprintf( '%d of %d locks could not be lifted.', count( $failed ), count( $results ) ) );
		}

		WP_CLI::success( sprintf( 'Unlocked %d username(s).', count( $results ) ) );
	}

	/**
	 * The storage the locks live in.
	 *
	 * @return StorageInterface
	 */
	private static function storage(): StorageInterface {
		return lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
	}
}
