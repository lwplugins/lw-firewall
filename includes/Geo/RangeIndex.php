<?php
/**
 * Sorted IPv4 range index for country lookups.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Geo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns a country's CIDR list into sorted integer ranges and searches them.
 *
 * Geo blocking is on by default with six countries, which is roughly 29,000
 * CIDRs. Without a Cloudflare header the previous lookup walked all of them,
 * parsing and masking each one, on every single request — an O(n) cost on the
 * earliest, cheapest layer of the firewall.
 *
 * IPv4 collapses to a pair of integers per range, so merged, sorted ranges can
 * be binary searched: roughly fifteen comparisons instead of thousands. IPv6
 * has no equivalent 32-bit form here and stays a CIDR list, which is short
 * enough for the linear path.
 */
final class RangeIndex {

	/**
	 * Cache format marker. A file without it is a plain CIDR list from an
	 * earlier version and is still read the old way, so an upgrade does not
	 * need the weekly refresh to have run first.
	 */
	public const FORMAT = 'lwfw-ranges-1';

	/**
	 * Build the stored structure for one country.
	 *
	 * Pure — no filesystem, no WordPress — so the packing is unit testable.
	 *
	 * @param array<int, string> $cidrs Raw CIDR lines.
	 * @return array{format: string, v4: array<int, array{0: int, 1: int}>, v6: array<int, string>}
	 */
	public static function build( array $cidrs ): array {
		$v4 = [];
		$v6 = [];

		foreach ( $cidrs as $cidr ) {
			$range = self::to_range( (string) $cidr );

			if ( null !== $range ) {
				$v4[] = $range;
				continue;
			}

			if ( str_contains( (string) $cidr, ':' ) ) {
				$v6[] = trim( (string) $cidr );
			}
		}

		return [
			'format' => self::FORMAT,
			'v4'     => self::merge( $v4 ),
			'v6'     => array_values( array_unique( $v6 ) ),
		];
	}

	/**
	 * Pack merged ranges into a flat binary blob.
	 *
	 * Eight bytes per range, two big-endian uint32s. A PHP array literal of
	 * 29,000 nested pairs costs real time to build on every include — the
	 * parse, not the search, was what made the linear lookup expensive. A
	 * string is read in one call and searched in place, with no array to
	 * construct at all.
	 *
	 * @param array<int, array{0: int, 1: int}> $ranges Sorted, merged ranges.
	 * @return string
	 */
	public static function pack_ranges( array $ranges ): string {
		$out = '';

		foreach ( $ranges as $range ) {
			$out .= pack( 'NN', $range[0] & 0xFFFFFFFF, $range[1] & 0xFFFFFFFF );
		}

		return $out;
	}

	/**
	 * Binary search a packed blob.
	 *
	 * @param string $ip     Dotted-quad address.
	 * @param string $packed Blob from pack_ranges().
	 * @return bool
	 */
	public static function packed_contains( string $ip, string $packed ): bool {
		$long = ip2long( $ip );

		if ( false === $long || '' === $packed ) {
			return false;
		}

		$needle = $long & 0xFFFFFFFF;
		$count  = intdiv( strlen( $packed ), 8 );
		$low    = 0;
		$high   = $count - 1;

		while ( $low <= $high ) {
			$mid  = intdiv( $low + $high, 2 );
			$pair = unpack( 'Nstart/Nend', substr( $packed, $mid * 8, 8 ) );

			if ( false === $pair ) {
				return false;
			}

			if ( $needle < $pair['start'] ) {
				$high = $mid - 1;
				continue;
			}

			if ( $needle > $pair['end'] ) {
				$low = $mid + 1;
				continue;
			}

			return true;
		}

		return false;
	}

	/**
	 * Whether an IPv4 address falls inside the index.
	 *
	 * @param string                            $ip     Dotted-quad address.
	 * @param array<int, array{0: int, 1: int}> $ranges Sorted, merged ranges.
	 * @return bool
	 */
	public static function contains( string $ip, array $ranges ): bool {
		$packed = ip2long( $ip );

		if ( false === $packed || empty( $ranges ) ) {
			return false;
		}

		// ip2long() returns a signed int on 32-bit builds; the ranges are built
		// the same way, so the comparison stays consistent either way.
		$low  = 0;
		$high = count( $ranges ) - 1;

		while ( $low <= $high ) {
			$mid = intdiv( $low + $high, 2 );

			if ( $packed < $ranges[ $mid ][0] ) {
				$high = $mid - 1;
				continue;
			}

			if ( $packed > $ranges[ $mid ][1] ) {
				$low = $mid + 1;
				continue;
			}

			return true;
		}

		return false;
	}

	/**
	 * Convert one IPv4 CIDR to an inclusive [start, end] pair.
	 *
	 * @param string $cidr CIDR notation.
	 * @return array{0: int, 1: int}|null Null when it is not a valid IPv4 CIDR.
	 */
	public static function to_range( string $cidr ): ?array {
		$parts = explode( '/', trim( $cidr ), 2 );

		if ( 2 !== count( $parts ) || ! ctype_digit( trim( $parts[1] ) ) ) {
			return null;
		}

		$base = ip2long( $parts[0] );
		$bits = (int) trim( $parts[1] );

		if ( false === $base || $bits > 32 ) {
			return null;
		}

		$size  = 32 === $bits ? 1 : ( 1 << ( 32 - $bits ) );
		$start = $base & ( 32 === $bits ? -1 : ~( $size - 1 ) );

		return [ $start, $start + $size - 1 ];
	}

	/**
	 * Sort and merge overlapping or adjacent ranges.
	 *
	 * Country feeds list many neighbouring blocks; merging them turns tens of
	 * thousands of entries into a far shorter list to search.
	 *
	 * @param array<int, array{0: int, 1: int}> $ranges Raw ranges.
	 * @return array<int, array{0: int, 1: int}>
	 */
	public static function merge( array $ranges ): array {
		if ( empty( $ranges ) ) {
			return [];
		}

		usort( $ranges, static fn ( array $a, array $b ): int => $a[0] <=> $b[0] );

		$merged  = [];
		$current = array_shift( $ranges );

		foreach ( $ranges as $range ) {
			if ( $range[0] <= $current[1] + 1 ) {
				$current[1] = max( $current[1], $range[1] );
				continue;
			}

			$merged[] = $current;
			$current  = $range;
		}

		$merged[] = $current;

		return $merged;
	}
}
