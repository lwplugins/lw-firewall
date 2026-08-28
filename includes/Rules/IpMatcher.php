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

			// Exact match — compare canonical packed bytes so IPv6 notation
			// differences (letter case, zero-compression) still match the
			// canonical form IpDetector produces.
			$packed_entry = inet_pton( $entry );

			if ( false !== $packed_entry && $packed_entry === $packed ) {
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
		$parts = explode( '/', $cidr, 2 );

		if ( 2 !== count( $parts ) ) {
			return false;
		}

		$prefix = trim( $parts[1] );

		// The prefix must be an exact decimal number. Casting it straight to int
		// is what made a typo catastrophic: (int) 'foo' and (int) '-1' both
		// produce a zero-width mask, which matches EVERY address of the same
		// family — silently turning one bad whitelist line into "firewall off",
		// or one bad blacklist line into "site down".
		if ( '' === $prefix || ! ctype_digit( $prefix ) ) {
			return false;
		}

		$packed_range = inet_pton( $parts[0] );

		if ( false === $packed_range ) {
			return false;
		}

		$bits = (int) $prefix;

		// 0-32 for IPv4, 0-128 for IPv6. A wider prefix is not a wider match,
		// it is a malformed rule.
		if ( $bits > strlen( $packed_range ) * 8 ) {
			return false;
		}

		// Different address families (IPv4 vs IPv6) never match. Without this,
		// PHP's string `&` truncates to the shorter operand and an IPv4 can
		// collide with the first 4 bytes of an IPv6 range (and vice versa).
		if ( strlen( $packed ) !== strlen( $packed_range ) ) {
			return false;
		}

		$mask = str_repeat( "\xff", (int) ( $bits / 8 ) );

		if ( 0 !== $bits % 8 ) {
			$mask .= chr( ( 0xff << ( 8 - ( $bits % 8 ) ) ) & 0xff );
		}

		$mask = str_pad( $mask, strlen( $packed ), "\x00" );

		return ( $packed & $mask ) === ( $packed_range & $mask );
	}
}
