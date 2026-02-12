<?php
/**
 * Client IP detection with Cloudflare support.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Detects the real client IP, trusting CF-Connecting-IP when behind Cloudflare.
 */
final class IpDetector {

	/**
	 * Cloudflare IP ranges (IPv4).
	 *
	 * @var string[]
	 */
	private const CF_RANGES = [
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
	];

	/**
	 * Detect the real client IP address.
	 *
	 * Checks CF-Connecting-IP first (if behind Cloudflare),
	 * then falls back to REMOTE_ADDR.
	 */
	public static function get_ip(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- IP addresses are validated by filter_var below.
		$remote_addr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

		// If CF-Connecting-IP is present and request comes from a Cloudflare IP, trust it.
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && self::is_cloudflare_ip( $remote_addr ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Validated via filter_var in sanitize_ip().
			return self::sanitize_ip( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		}

		return self::sanitize_ip( $remote_addr );
	}

	/**
	 * Check if an IP belongs to Cloudflare.
	 *
	 * @param string $ip IP address to check.
	 * @return bool
	 */
	private static function is_cloudflare_ip( string $ip ): bool {
		$packed = inet_pton( $ip );

		if ( false === $packed ) {
			return false;
		}

		foreach ( self::CF_RANGES as $range ) {
			if ( self::ip_in_range( $packed, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if a packed IP is within a CIDR range.
	 *
	 * @param string $packed_ip Binary representation of the IP.
	 * @param string $cidr      CIDR notation range (e.g. 10.0.0.0/8).
	 * @return bool
	 */
	private static function ip_in_range( string $packed_ip, string $cidr ): bool {
		[ $range, $bits ] = explode( '/', $cidr );
		$bits             = (int) $bits;
		$packed_range     = inet_pton( $range );

		if ( false === $packed_range ) {
			return false;
		}

		$mask = str_repeat( "\xff", (int) ( $bits / 8 ) );
		if ( 0 !== $bits % 8 ) {
			$mask .= chr( 0xff << ( 8 - ( $bits % 8 ) ) );
		}
		$mask = str_pad( $mask, strlen( $packed_ip ), "\x00" );

		return ( $packed_ip & $mask ) === ( $packed_range & $mask );
	}

	/**
	 * Sanitize an IP address string.
	 *
	 * @param string $ip Raw IP address.
	 * @return string Validated IP or '0.0.0.0'.
	 */
	private static function sanitize_ip( string $ip ): string {
		$ip = trim( $ip );

		// Handle comma-separated IPs (take first).
		if ( str_contains( $ip, ',' ) ) {
			$ip = trim( explode( ',', $ip )[0] );
		}

		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}
}
