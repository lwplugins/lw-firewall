<?php
/**
 * Firewall Geo Blocking CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\Geo\CidrUpdater;
use LightweightPlugins\Firewall\CLI\Support\ConfigOpsTrait;
use LightweightPlugins\Firewall\Options;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage geo blocking (blocked countries).
 */
final class GeoCommand {

	use ConfigOpsTrait;

	/**
	 * List blocked country codes.
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
	 *     $ wp lw-firewall geo list
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 *
	 * @subcommand list
	 */
	public function list_countries( array $args, array $assoc_args ): void {
		$format    = Utils\get_flag_value( $assoc_args, 'format', 'table' );
		$countries = (array) Options::get( 'blocked_countries', [] );
		$enabled   = (bool) Options::get( 'geo_enabled', false );

		if ( ! $enabled ) {
			WP_CLI::warning( 'Geo blocking is currently disabled.' );
		}

		if ( empty( $countries ) ) {
			WP_CLI::log( 'No blocked countries configured.' );
			return;
		}

		$items = [];
		foreach ( $countries as $i => $cc ) {
			$stale   = CidrUpdater::is_stale( $cc );
			$items[] = [
				'#'      => $i + 1,
				'code'   => $cc,
				'cached' => $stale ? 'stale' : 'ok',
			];
		}

		Utils\format_items( $format, $items, [ '#', 'code', 'cached' ] );
	}

	/**
	 * Add a country code to the blocked list.
	 *
	 * ## OPTIONS
	 *
	 * <code>
	 * : ISO 3166-1 alpha-2 country code (e.g. CN, RU, IN).
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall geo add CN
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function add( array $args, array $assoc_args ): void {
		$cc        = strtoupper( trim( (string) $args[0] ) );
		$countries = self::resolve_list_or_fail( 'blocked_countries' );

		if ( in_array( $cc, $countries, true ) ) {
			WP_CLI::error( "'{$cc}' is already in the blocked list." );
		}

		// The input layer rejects anything that is not an assigned ISO code.
		$countries[] = $cc;
		self::save_list( 'blocked_countries', $countries );

		if ( in_array( 'geo_enabled', Options::overridden(), true ) ) {
			WP_CLI::success( "Added '{$cc}' to blocked countries. Geo blocking is pinned in wp-config.php and was left as is." );
			return;
		}

		self::save_value( 'geo_enabled', true );
		WP_CLI::success( "Added '{$cc}' to blocked countries. Geo blocking enabled." );
	}

	/**
	 * Remove a country code from the blocked list.
	 *
	 * ## OPTIONS
	 *
	 * <code>
	 * : Country code to remove.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall geo remove CN
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function remove( array $args, array $assoc_args ): void {
		$cc        = strtoupper( trim( (string) $args[0] ) );
		$countries = self::resolve_list_or_fail( 'blocked_countries' );
		$filtered  = array_values( array_filter( $countries, static fn ( string $c ): bool => $c !== $cc ) );

		if ( count( $filtered ) === count( $countries ) ) {
			WP_CLI::error( "'{$cc}' was not found in the blocked list." );
		}

		self::save_list( 'blocked_countries', $filtered );

		WP_CLI::success( "Removed '{$cc}' from blocked countries." );
	}

	/**
	 * Update CIDR cache for all blocked countries.
	 *
	 * Downloads aggregated IPv4 and IPv6 CIDR lists from ipdeny.com.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall geo update
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function update( array $args, array $assoc_args ): void {
		$countries = (array) Options::get( 'blocked_countries', [] );

		if ( empty( $countries ) ) {
			WP_CLI::error( 'No blocked countries configured.' );
		}

		foreach ( $countries as $cc ) {
			$result = CidrUpdater::update_country( $cc );

			if ( $result ) {
				WP_CLI::log( "Updated CIDR cache for {$cc}." );
			} else {
				WP_CLI::warning( "Failed to update {$cc}." );
			}
		}

		WP_CLI::success( 'CIDR cache update complete.' );
	}
}
