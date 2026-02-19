<?php
/**
 * CIDR list updater for Geo Blocking.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Geo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Downloads and caches aggregated CIDR lists per country from ipdeny.com.
 */
final class CidrUpdater {

	/**
	 * Source URL template. %s = lowercase country code.
	 */
	private const SOURCE_URL = 'https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone';

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
		$cc  = strtolower( $cc );
		$url = sprintf( self::SOURCE_URL, $cc );

		$response = wp_remote_get(
			$url,
			[
				'timeout'   => 30,
				'sslverify' => true,
			]
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$code = wp_remote_retrieve_response_code( $response );

		if ( 200 !== $code ) {
			return false;
		}

		$body  = wp_remote_retrieve_body( $response );
		$cidrs = array_filter( array_map( 'trim', explode( "\n", $body ) ) );

		if ( empty( $cidrs ) ) {
			return false;
		}

		return self::write_cache( $cc, $cidrs );
	}

	/**
	 * Check if a country's cache is stale (older than 7 days).
	 *
	 * @param string $cc Country code.
	 * @return bool
	 */
	public static function is_stale( string $cc ): bool {
		$file = self::get_cache_dir() . strtolower( $cc ) . '.php';

		if ( ! file_exists( $file ) ) {
			return true;
		}

		$age = time() - (int) filemtime( $file );

		return $age > self::STALE_SECONDS;
	}

	/**
	 * Write CIDR array to a PHP cache file.
	 *
	 * @param string   $cc    Lowercase country code.
	 * @param string[] $cidrs CIDR list.
	 * @return bool
	 */
	private static function write_cache( string $cc, array $cidrs ): bool {
		$dir = self::get_cache_dir();

		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$content = "<?php\nreturn " . var_export( array_values( $cidrs ), true ) . ";\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		return false !== file_put_contents( $dir . $cc . '.php', $content );
	}
}
