<?php
/**
 * Ban management CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\IpSubject;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rules\AutoBanner;
use LightweightPlugins\Firewall\Rules\BanList;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Inspect and lift automatic IP bans.
 */
final class BanCommand {

	/**
	 * List currently banned IP addresses.
	 *
	 * The `active` column reconciles the index against the storage backend: an
	 * entry marked `no` is tracked but no longer enforced, which happens after
	 * a Redis flush, an APCu restart, or a cleared file cache.
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
	 *     $ wp lw-firewall ban list
	 *     $ wp lw-firewall ban list --format=json
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 *
	 * @subcommand list
	 */
	public function list_bans( array $args, array $assoc_args ): void {
		unset( $args );

		$rows = BanList::all( self::storage() );

		if ( empty( $rows ) ) {
			WP_CLI::log( 'No banned IP addresses.' );
			return;
		}

		$items = [];

		foreach ( $rows as $row ) {
			$items[] = [
				'ip'      => $row['ip'],
				'reason'  => '' !== $row['reason'] ? $row['reason'] : 'unknown',
				'banned'  => $row['time'] > 0 ? gmdate( 'Y-m-d H:i:s', $row['time'] ) . ' UTC' : 'unknown',
				'expires' => gmdate( 'Y-m-d H:i:s', $row['expires'] ) . ' UTC',
				'active'  => $row['active'] ? 'yes' : 'no',
			];
		}

		Utils\format_items(
			(string) Utils\get_flag_value( $assoc_args, 'format', 'table' ),
			$items,
			[ 'ip', 'reason', 'banned', 'expires', 'active' ]
		);
	}

	/**
	 * Check whether one IP address is currently banned.
	 *
	 * Reads the storage backend directly, so it answers for any ban — including
	 * one placed before this index existed.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address to check, or an IPv6 /64 as `ban list` shows it.
	 *   IPv6 bans cover the whole /64.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall ban check 203.0.113.42
	 *
	 * @param array<int, string>   $args       Positional arguments.
	 * @param array<string, mixed> $assoc_args Associative arguments (unused).
	 *
	 * @subcommand check
	 */
	public function check( array $args, array $assoc_args ): void {
		unset( $assoc_args );

		$ip = self::validate_ip( $args[0] ?? '' );

		if ( ( new AutoBanner( self::storage() ) )->is_banned( $ip ) ) {
			WP_CLI::warning( sprintf( '%s is banned.', $ip ) );
			return;
		}

		WP_CLI::success( sprintf( '%s is not banned.', $ip ) );
	}

	/**
	 * Lift the ban on one IP address.
	 *
	 * Also clears the counters that produced the ban — the rate-limit,
	 * failed-login, registration, password-reset and 404 counters — so the next
	 * request from that address starts from zero instead of re-banning it
	 * immediately.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address to unban, or an IPv6 /64 as `ban list` shows it.
	 *   Any address inside a banned /64 lifts the ban on the whole /64.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall ban remove 203.0.113.42
	 *
	 * @param array<int, string>   $args       Positional arguments.
	 * @param array<string, mixed> $assoc_args Associative arguments (unused).
	 *
	 * @subcommand remove
	 */
	public function remove( array $args, array $assoc_args ): void {
		unset( $assoc_args );

		$ip = self::validate_ip( $args[0] ?? '' );

		if ( ! ( new AutoBanner( self::storage() ) )->unban( $ip ) ) {
			WP_CLI::error( sprintf( 'Could not lift the ban on %s — the storage backend refused the delete.', $ip ) );
		}

		WP_CLI::success( sprintf( '%s unbanned and its counters cleared.', $ip ) );
	}

	/**
	 * Lift every tracked ban.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall ban clear --yes
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 *
	 * @subcommand clear
	 */
	public function clear( array $args, array $assoc_args ): void {
		unset( $args );

		$rows = BanList::all();

		if ( empty( $rows ) ) {
			WP_CLI::success( 'No banned IP addresses to clear.' );
			return;
		}

		WP_CLI::confirm( sprintf( 'Lift all %d tracked bans?', count( $rows ) ), $assoc_args );

		$banner = new AutoBanner( self::storage() );

		foreach ( $rows as $row ) {
			$banner->unban( $row['ip'] );
		}

		BanList::clear();

		WP_CLI::success( sprintf( 'Lifted %d ban(s).', count( $rows ) ) );
	}

	/**
	 * Resolve the configured storage backend.
	 *
	 * @return \LightweightPlugins\Firewall\Storage\StorageInterface
	 */
	private static function storage() {
		return lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
	}

	/**
	 * Validate a positional IP argument, or abort.
	 *
	 * @param string $ip Raw argument.
	 * @return string
	 */
	private static function validate_ip( string $ip ): string {
		$ip = trim( $ip );

		if ( '' === IpSubject::parse( $ip ) ) {
			WP_CLI::error( 'Please pass a valid IP address or IPv6 /64.' );
		}

		return $ip;
	}
}
