<?php
/**
 * IP matching against whitelist/blacklist.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Matches an IP against a list of IPs or CIDR ranges.
 */
final class IpMatcher {

	/**
	 * Check if an IP matches any entry in a list.
	 *
	 * Supports individual IPs and CIDR notation.
	 *
	 * @param string   $ip   IP address to check.
	 * @param string[] $list List of IPs or CIDR ranges.
	 * @return bool
	 */
	public static function matches( string $ip, array $list ): bool {
		if ( empty( $list ) ) {
			return false;
		}

		$packed = inet_pton( $ip );

		if ( false === $packed ) {
			return false;
		}

		foreach ( $list as $entry ) {
			$entry = trim( $entry );

			if ( '' === $entry ) {
				continue;
			}

			// CIDR range.
			if ( str_contains( $entry, '/' ) ) {
				if ( self::ip_in_cidr( $packed, $entry ) ) {
					return true;
				}
				continue;
			}

			// Exact match.
			if ( $ip === $entry ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if a packed IP is within a CIDR range.
	 *
	 * @param string $packed Packed IP (from inet_pton).
	 * @param string $cidr   CIDR notation (e.g. 10.0.0.0/8).
	 * @return bool
	 */
	private static function ip_in_cidr( string $packed, string $cidr ): bool {
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

		$mask = str_pad( $mask, strlen( $packed ), "\x00" );

		return ( $packed & $mask ) === ( $packed_range & $mask );
	}
}
