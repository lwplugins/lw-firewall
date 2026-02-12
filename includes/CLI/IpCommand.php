<?php
/**
 * Firewall IP rules CLI command.
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
 * Manage IP whitelist and blacklist.
 */
final class IpCommand {

	/**
	 * List IPs in a whitelist or blacklist.
	 *
	 * ## OPTIONS
	 *
	 * <type>
	 * : The list type.
	 * ---
	 * options:
	 *   - whitelist
	 *   - blacklist
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
	 *     $ wp lw-firewall ip list whitelist
	 *     $ wp lw-firewall ip list blacklist
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 *
	 * @subcommand list
	 */
	public function list_ips( array $args, array $assoc_args ): void {
		$type   = $args[0];
		$key    = 'ip_' . $type;
		$format = Utils\get_flag_value( $assoc_args, 'format', 'table' );
		$ips    = (array) Options::get( $key, [] );

		if ( empty( $ips ) ) {
			WP_CLI::log( "No IPs in {$type}." );
			return;
		}

		$items = [];
		foreach ( $ips as $i => $ip ) {
			$items[] = [
				'#'  => $i + 1,
				'ip' => $ip,
			];
		}

		Utils\format_items( $format, $items, [ '#', 'ip' ] );
	}

	/**
	 * Add an IP or CIDR range to a list.
	 *
	 * ## OPTIONS
	 *
	 * <type>
	 * : The list type.
	 * ---
	 * options:
	 *   - whitelist
	 *   - blacklist
	 * ---
	 *
	 * <ip>
	 * : IP address or CIDR range (e.g. 1.2.3.4 or 10.0.0.0/8).
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall ip add whitelist 192.168.1.100
	 *     $ wp lw-firewall ip add blacklist 10.0.0.0/8
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function add( array $args, array $assoc_args ): void {
		[ $type, $ip ] = $args;
		$key           = 'ip_' . $type;
		$ips           = (array) Options::get( $key, [] );

		if ( in_array( $ip, $ips, true ) ) {
			WP_CLI::error( "'{$ip}' is already in the {$type}." );
		}

		$ips[]           = $ip;
		$current         = Options::get_all();
		$current[ $key ] = $ips;

		if ( Options::save( $current ) ) {
			WP_CLI::success( "Added '{$ip}' to {$type}." );
		} else {
			WP_CLI::error( "Failed to update {$type}." );
		}
	}

	/**
	 * Remove an IP or CIDR range from a list.
	 *
	 * ## OPTIONS
	 *
	 * <type>
	 * : The list type.
	 * ---
	 * options:
	 *   - whitelist
	 *   - blacklist
	 * ---
	 *
	 * <ip>
	 * : IP address or CIDR range to remove.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall ip remove whitelist 192.168.1.100
	 *     $ wp lw-firewall ip remove blacklist 10.0.0.0/8
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function remove( array $args, array $assoc_args ): void {
		[ $type, $ip ] = $args;
		$key           = 'ip_' . $type;
		$ips           = (array) Options::get( $key, [] );
		$found         = false;

		$ips = array_values(
			array_filter(
				$ips,
				static function ( $existing ) use ( $ip, &$found ): bool {
					if ( (string) $existing === $ip ) {
						$found = true;
						return false;
					}
					return true;
				}
			)
		);

		if ( ! $found ) {
			WP_CLI::error( "'{$ip}' was not found in {$type}." );
		}

		$current         = Options::get_all();
		$current[ $key ] = $ips;

		if ( Options::save( $current ) ) {
			WP_CLI::success( "Removed '{$ip}' from {$type}." );
		} else {
			WP_CLI::error( "Failed to update {$type}." );
		}
	}
}
