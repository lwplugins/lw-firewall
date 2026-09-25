<?php
/**
 * Geo Blocking Detector.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Geo;

use LightweightPlugins\Firewall\IpDetector;

use LightweightPlugins\Firewall\Options;
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
	 * Load a country's metadata file once per request.
	 *
	 * @param string $file Absolute path.
	 * @return array<string, mixed>|null
	 */
	private static function load( string $file ): ?array {
		static $cache = [];

		if ( ! array_key_exists( $file, $cache ) ) {
			$data           = include $file;
			$cache[ $file ] = is_array( $data ) ? $data : null;
		}

		return $cache[ $file ];
	}

	/**
	 * Load a country's packed ranges (IPv4 or IPv6 blob) once per request.
	 *
	 * @param string $file Absolute path to the .bin blob.
	 * @return string
	 */
	private static function load_packed( string $file ): string {
		static $cache = [];

		if ( ! array_key_exists( $file, $cache ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- Local cache blob; a missing file simply means no ranges.
			$raw            = file_exists( $file ) ? @file_get_contents( $file ) : false;
			$cache[ $file ] = false === $raw ? '' : $raw;
		}

		return $cache[ $file ];
	}

	/**
	 * Get country code from Cloudflare header.
	 *
	 * @return string Uppercase 2-letter code or empty string.
	 */
	private static function get_cf_country(): string {
		// The country header decides whether the CIDR fallback runs at all, so
		// it has to clear the same trust test as the client IP. Accepting it
		// from any source let a visitor of a blocked country send
		// "CF-IPCountry: US" straight to the origin and skip geo blocking
		// entirely — any non-empty value was enough.
		if ( ! IpDetector::is_cloudflare_request() ) {
			return '';
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Shape validated below.
		$header = strtoupper( trim( (string) ( $_SERVER['HTTP_CF_IPCOUNTRY'] ?? '' ) ) );

		// XX is "unknown", T1 is Tor. Both mean "no country", so the CIDR
		// fallback should decide instead.
		if ( '' === $header || 'XX' === $header || 'T1' === $header ) {
			return '';
		}

		// Exactly two letters, or it is not a country code — a malformed value
		// must not short-circuit the fallback either.
		if ( 1 !== preg_match( '/^[A-Z]{2}$/', $header ) ) {
			return '';
		}

		return $header;
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
		$is_v6     = str_contains( $ip, ':' );

		foreach ( $blocked_countries as $cc ) {
			// Defensive: never turn an unvalidated value into an include() path.
			if ( ! Options::is_country_code( (string) $cc ) ) {
				continue;
			}

			$file = $cache_dir . strtolower( (string) $cc ) . '.php';

			if ( ! file_exists( $file ) ) {
				continue; // Fail-open: no cache = no block.
			}

			$data = self::load( $file );

			if ( ! is_array( $data ) ) {
				continue;
			}

			// A cache written before the packed format is still a plain CIDR
			// list, so an upgrade keeps working until the weekly refresh runs.
			if ( ( $data['format'] ?? '' ) !== RangeIndex::FORMAT ) {
				if ( IpMatcher::matches( $ip, $data ) ) {
					return true;
				}

				continue;
			}

			// Each family has its own blob; only the visitor's is read.
			$base = substr( $file, 0, -4 );

			if ( $is_v6
				? RangeIndex6::contains( $ip, self::load_packed( $base . '.v6.bin' ) )
				: RangeIndex::packed_contains( $ip, self::load_packed( $base . '.bin' ) )
			) {
				return true;
			}

			if ( ! empty( $data['v6'] ) && IpMatcher::matches( $ip, (array) $data['v6'] ) ) {
				return true;
			}
		}

		return false;
	}
}
