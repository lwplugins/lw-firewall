<?php
/**
 * Sorted IPv6 range index for country lookups.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Geo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The IPv6 counterpart of RangeIndex.
 *
 * A country's IPv6 feed is a few thousand CIDRs; six default countries add up
 * to over ten thousand. Walking them linearly on every IPv6 request cost
 * milliseconds at the earliest layer of the firewall, so each CIDR becomes an
 * inclusive [start, end] pair of 16-byte network-order strings, overlapping
 * pairs are merged, and the result is packed into one blob (32 bytes per
 * range) that is binary searched in place. Network byte order makes a plain
 * binary string comparison the numeric one.
 */
final class RangeIndex6 {

	/**
	 * Bytes per packed range: 16 for the start, 16 for the end.
	 */
	private const WIDTH = 32;

	/**
	 * Build the packed index from raw CIDR lines.
	 *
	 * Pure — no filesystem, no WordPress. Lines that are not valid IPv6 CIDRs
	 * are skipped.
	 *
	 * @param array<int, string> $cidrs Raw CIDR lines.
	 * @return string
	 */
	public static function build( array $cidrs ): string {
		$ranges = [];

		foreach ( $cidrs as $cidr ) {
			$range = self::to_range( (string) $cidr );

			if ( null !== $range ) {
				$ranges[] = $range;
			}
		}

		usort( $ranges, static fn ( array $a, array $b ): int => strcmp( $a[0], $b[0] ) );

		$merged = [];

		foreach ( $ranges as $range ) {
			$last = count( $merged ) - 1;

			if ( $last >= 0 && strcmp( $range[0], $merged[ $last ][1] ) <= 0 ) {
				if ( strcmp( $range[1], $merged[ $last ][1] ) > 0 ) {
					$merged[ $last ][1] = $range[1];
				}
				continue;
			}

			$merged[] = $range;
		}

		return implode( '', array_map( static fn ( array $r ): string => $r[0] . $r[1], $merged ) );
	}

	/**
	 * Whether an IPv6 address falls inside a packed index.
	 *
	 * @param string $ip     Client address.
	 * @param string $packed Blob from build().
	 * @return bool
	 */
	public static function contains( string $ip, string $packed ): bool {
		if ( '' === $packed || ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return false;
		}

		$needle = (string) inet_pton( $ip );
		$low    = 0;
		$high   = intdiv( strlen( $packed ), self::WIDTH ) - 1;

		while ( $low <= $high ) {
			$mid    = intdiv( $low + $high, 2 );
			$offset = $mid * self::WIDTH;

			if ( strcmp( $needle, substr( $packed, $offset, 16 ) ) < 0 ) {
				$high = $mid - 1;
				continue;
			}

			if ( strcmp( $needle, substr( $packed, $offset + 16, 16 ) ) > 0 ) {
				$low = $mid + 1;
				continue;
			}

			return true;
		}

		return false;
	}

	/**
	 * Convert one IPv6 CIDR to an inclusive [start, end] pair.
	 *
	 * @param string $cidr CIDR notation.
	 * @return array{0: string, 1: string}|null Null when it is not a valid IPv6 CIDR.
	 */
	private static function to_range( string $cidr ): ?array {
		$parts = explode( '/', trim( $cidr ), 2 );

		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[1] ) || (int) $parts[1] > 128 ) {
			return null;
		}

		if ( ! filter_var( $parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return null;
		}

		$bits = (int) $parts[1];
		$mask = str_repeat( "\xff", intdiv( $bits, 8 ) );

		if ( 0 !== $bits % 8 ) {
			$mask .= chr( ( 0xff << ( 8 - $bits % 8 ) ) & 0xff );
		}

		$mask  = str_pad( $mask, 16, "\x00" );
		$start = (string) inet_pton( $parts[0] ) & $mask;

		return [ $start, $start | ~$mask ];
	}
}
