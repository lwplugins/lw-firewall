<?php
/**
 * CIDR list updater for Geo Blocking.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Geo;

use LightweightPlugins\Firewall\Storage\CacheDirectory;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Downloads and caches aggregated CIDR lists per country from ipdeny.com.
 *
 * Both address families are fetched. Each family is written independently:
 * a failed download for one keeps the other's fresh result and leaves the
 * previous cache for the failed family in place.
 */
final class CidrUpdater {

	/**
	 * IPv4 source URL template. %s = lowercase country code.
	 */
	private const SOURCE_URL = 'https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone';

	/**
	 * IPv6 source URL template. %s = lowercase country code.
	 */
	private const SOURCE_URL_V6 = 'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/%s-aggregated.zone';

	/**
	 * Cache staleness threshold in seconds (7 days).
	 */
	private const STALE_SECONDS = 604800;

	/**
	 * WP Cron hook name.
	 */
	public const CRON_HOOK = 'lw_firewall_geo_update';

	/**
	 * Get cache directory path.
	 *
	 * @return string Path with trailing slash.
	 */
	public static function get_cache_dir(): string {
		return WP_CONTENT_DIR . '/cache/lw-firewall/geo/';
	}

	/**
	 * Update CIDR cache for all given country codes.
	 *
	 * @param string[] $country_codes Uppercase 2-letter codes.
	 * @return void
	 */
	public static function update( array $country_codes ): void {
		foreach ( $country_codes as $cc ) {
			self::update_country( $cc );
		}
	}

	/**
	 * Download and cache CIDR list for a single country.
	 *
	 * @param string $cc Uppercase 2-letter country code.
	 * @return bool True on success.
	 */
	public static function update_country( string $cc ): bool {
		// Defensive: never build a URL or cache-file path from an unvalidated
		// code (guards the write_cache() path against traversal).
		if ( ! Options::is_country_code( $cc ) ) {
			return false;
		}

		$cc = strtolower( $cc );
		$v4 = self::fetch( sprintf( self::SOURCE_URL, $cc ) );
		$v6 = self::fetch( sprintf( self::SOURCE_URL_V6, $cc ) );

		if ( null === $v4 && null === $v6 ) {
			return false;
		}

		return self::write_cache( $cc, self::cache_files( $v4, $v6 ) );
	}

	/**
	 * Download one zone file.
	 *
	 * @param string $url Zone URL.
	 * @return array<int, string>|null CIDR lines, or null when the download failed or was empty.
	 */
	private static function fetch( string $url ): ?array {
		$response = wp_remote_get(
			$url,
			[
				'timeout'   => 30,
				'sslverify' => true,
			]
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$cidrs = self::parse_zone( wp_remote_retrieve_body( $response ) );

		return empty( $cidrs ) ? null : $cidrs;
	}

	/**
	 * Split a zone file body into trimmed, non-empty lines.
	 *
	 * @param string $body Raw body.
	 * @return array<int, string>
	 */
	public static function parse_zone( string $body ): array {
		return array_values( array_filter( array_map( 'trim', explode( "\n", $body ) ) ) );
	}

	/**
	 * The cache files one update produces, keyed by extension.
	 *
	 * Pure — no filesystem. A family whose download failed (null) produces no
	 * file, so the previous one stays in place. The metadata file is always
	 * written: it carries the format marker the detector checks.
	 *
	 * @param array<int, string>|null $v4 IPv4 CIDR lines, or null.
	 * @param array<int, string>|null $v6 IPv6 CIDR lines, or null.
	 * @return array<string, string>
	 */
	public static function cache_files( ?array $v4, ?array $v6 ): array {
		$files = [];

		// The IPv4 ranges go into a flat binary blob: building a PHP array of
		// tens of thousands of pairs on every include cost more than the search
		// itself.
		if ( null !== $v4 ) {
			$files['bin'] = RangeIndex::pack_ranges( RangeIndex::build( $v4 )['v4'] );
		}

		if ( null !== $v6 ) {
			$files['v6.bin'] = RangeIndex6::build( $v6 );
		}

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Generating a PHP cache file, not debug output.
		$meta = var_export(
			[
				'format' => RangeIndex::FORMAT,
				'v6'     => [],
			],
			true
		);

		$files['php'] = "<?php\nreturn " . $meta . ";\n";

		return $files;
	}

	/**
	 * Check if a country's cache is stale (older than 7 days).
	 *
	 * @param string $cc Country code.
	 * @return bool
	 */
	public static function is_stale( string $cc ): bool {
		if ( ! Options::is_country_code( $cc ) ) {
			return true;
		}

		$file = self::get_cache_dir() . strtolower( $cc ) . '.php';

		if ( ! file_exists( $file ) ) {
			return true;
		}

		$age = time() - (int) filemtime( $file );

		return $age > self::STALE_SECONDS;
	}

	/**
	 * Write the cache files for one country.
	 *
	 * The blobs go first and the metadata file last, each atomically.
	 *
	 * @param string                $cc    Lowercase country code.
	 * @param array<string, string> $files Contents keyed by extension, from cache_files().
	 * @return bool
	 */
	private static function write_cache( string $cc, array $files ): bool {
		$dir = self::get_cache_dir();

		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		// wp_mkdir_p() creates the shared cache parent too, so guard both —
		// otherwise whichever component ran first decided whether the cache
		// directory was reachable over HTTP.
		CacheDirectory::protect( dirname( $dir ) . '/' );
		CacheDirectory::protect( $dir );

		$ok = true;

		foreach ( $files as $extension => $contents ) {
			$ok = self::write_atomic( $dir . $cc . '.' . $extension, $contents ) && $ok;
		}

		return $ok;
	}

	/**
	 * Write a cache file atomically.
	 *
	 * Temporary file plus rename, so a request reading the cache mid-update
	 * sees either the old file or the new one — never a half-written include,
	 * which would fail open.
	 *
	 * @param string $path     Destination.
	 * @param string $contents File body.
	 * @return bool
	 */
	private static function write_atomic( string $path, string $contents ): bool {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === file_put_contents( $path . '.tmp', $contents, LOCK_EX ) ) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- The atomic guarantee is the point; WP_Filesystem::move() does not offer one.
		return rename( $path . '.tmp', $path );
	}
}
