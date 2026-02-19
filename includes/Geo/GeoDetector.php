<?php
/**
 * Geo Blocking Detector.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Geo;

use LightweightPlugins\Firewall\Rules\IpMatcher;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Detects if an IP belongs to a blocked country.
 *
 * Uses CF-IPCountry header (Cloudflare) first, falls back to local CIDR cache.
 */
final class GeoDetector {

	/**
	 * Check if an IP is from a blocked country.
	 *
	 * @param string   $ip                Client IP address.
	 * @param string[] $blocked_countries  Uppercase country codes (e.g. ['IN', 'CN']).
	 * @return bool
	 */
	public static function is_blocked( string $ip, array $blocked_countries ): bool {
		if ( empty( $blocked_countries ) ) {
			return false;
		}

		// 1. Cloudflare header — instant, zero-cost.
		$cf_country = self::get_cf_country();

		if ( '' !== $cf_country ) {
			return in_array( $cf_country, $blocked_countries, true );
		}

		// 2. Local CIDR cache fallback.
		return self::matches_cidr_cache( $ip, $blocked_countries );
	}

	/**
	 * Get country code from Cloudflare header.
	 *
	 * @return string Uppercase 2-letter code or empty string.
	 */
	private static function get_cf_country(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$header = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? '';

		if ( '' === $header || 'XX' === $header || 'T1' === $header ) {
			return '';
		}

		return strtoupper( substr( (string) $header, 0, 2 ) );
	}

	/**
	 * Check IP against cached CIDR lists for blocked countries.
	 *
	 * @param string   $ip                Client IP.
	 * @param string[] $blocked_countries Country codes.
	 * @return bool
	 */
	private static function matches_cidr_cache( string $ip, array $blocked_countries ): bool {
		$cache_dir = CidrUpdater::get_cache_dir();

		foreach ( $blocked_countries as $cc ) {
			$file = $cache_dir . strtolower( $cc ) . '.php';

			if ( ! file_exists( $file ) ) {
				continue; // Fail-open: no cache = no block.
			}

			$cidrs = include $file;

			if ( ! is_array( $cidrs ) ) {
				continue;
			}

			if ( IpMatcher::matches( $ip, $cidrs ) ) {
				return true;
			}
		}

		return false;
	}
}
