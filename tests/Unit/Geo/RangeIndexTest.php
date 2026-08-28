<?php
/**
 * Tests for the packed country range index.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Geo;

use LightweightPlugins\Firewall\Geo\RangeIndex;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Geo\RangeIndex
 */
final class RangeIndexTest extends TestCase {

	public function test_converts_a_cidr_to_an_inclusive_range(): void {
		$this->assertSame(
			array( ip2long( '10.0.0.0' ), ip2long( '10.255.255.255' ) ),
			RangeIndex::to_range( '10.0.0.0/8' )
		);
	}

	public function test_a_single_host_range_covers_one_address(): void {
		$range = RangeIndex::to_range( '203.0.113.7/32' );

		$this->assertSame( $range[0], $range[1] );
		$this->assertSame( ip2long( '203.0.113.7' ), $range[0] );
	}

	/**
	 * Host bits set in the base address must not shift the range — feeds are
	 * not guaranteed to be normalised.
	 */
	public function test_host_bits_are_masked_off(): void {
		$this->assertSame(
			RangeIndex::to_range( '10.1.2.0/24' ),
			RangeIndex::to_range( '10.1.2.99/24' )
		);
	}

	/**
	 * @dataProvider provide_non_ipv4
	 *
	 * @param string $cidr Entry that is not an IPv4 CIDR.
	 */
	public function test_rejects_entries_that_are_not_ipv4_cidrs( string $cidr ): void {
		$this->assertNull( RangeIndex::to_range( $cidr ) );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_non_ipv4(): array {
		return array(
			'ipv6'         => array( '2001:db8::/32' ),
			'no prefix'    => array( '10.0.0.0' ),
			'bad prefix'   => array( '10.0.0.0/foo' ),
			'over 32'      => array( '10.0.0.0/33' ),
			'not an ip'    => array( 'nonsense/24' ),
			'empty'        => array( '' ),
		);
	}

	public function test_merges_adjacent_and_overlapping_ranges(): void {
		$merged = RangeIndex::merge(
			array(
				RangeIndex::to_range( '10.0.1.0/24' ),
				RangeIndex::to_range( '10.0.0.0/24' ),
				RangeIndex::to_range( '10.0.0.128/25' ),
				RangeIndex::to_range( '192.0.2.0/24' ),
			)
		);

		$this->assertCount( 2, $merged );
		$this->assertSame( ip2long( '10.0.0.0' ), $merged[0][0] );
		$this->assertSame( ip2long( '10.0.1.255' ), $merged[0][1] );
	}

	public function test_finds_an_address_inside_a_range(): void {
		$index = RangeIndex::build( array( '10.0.0.0/8', '192.0.2.0/24' ) );

		$this->assertTrue( RangeIndex::contains( '10.4.5.6', $index['v4'] ) );
		$this->assertTrue( RangeIndex::contains( '192.0.2.99', $index['v4'] ) );
	}

	public function test_rejects_an_address_outside_every_range(): void {
		$index = RangeIndex::build( array( '10.0.0.0/8', '192.0.2.0/24' ) );

		$this->assertFalse( RangeIndex::contains( '203.0.113.7', $index['v4'] ) );
		$this->assertFalse( RangeIndex::contains( '11.0.0.1', $index['v4'] ) );
	}

	/**
	 * The binary search must agree with a linear scan across the whole set,
	 * including the boundary addresses where an off-by-one would hide.
	 */
	public function test_agrees_with_a_linear_scan_on_boundaries(): void {
		$cidrs = array( '10.0.0.0/24', '10.0.2.0/24', '172.16.0.0/12', '203.0.113.0/29' );
		$index = RangeIndex::build( $cidrs );

		foreach ( array( '9.255.255.255', '10.0.0.0', '10.0.0.255', '10.0.1.0', '10.0.2.0',
			'172.15.255.255', '172.16.0.0', '172.31.255.255', '172.32.0.0',
			'203.0.113.0', '203.0.113.7', '203.0.113.8' ) as $ip ) {

			$expected = false;

			foreach ( $cidrs as $cidr ) {
				$range = RangeIndex::to_range( $cidr );
				$long  = ip2long( $ip );

				if ( $long >= $range[0] && $long <= $range[1] ) {
					$expected = true;
					break;
				}
			}

			$this->assertSame(
				$expected,
				RangeIndex::contains( $ip, $index['v4'] ),
				sprintf( '%s classified differently by the index', $ip )
			);
		}
	}

	public function test_keeps_ipv6_entries_for_the_linear_path(): void {
		$index = RangeIndex::build( array( '10.0.0.0/8', '2001:db8::/32' ) );

		$this->assertSame( array( '2001:db8::/32' ), $index['v6'] );
		$this->assertCount( 1, $index['v4'] );
	}

	/**
	 * The packed blob and the array form must agree exactly — the blob is what
	 * actually runs, and a mismatch would silently change who gets blocked.
	 */
	public function test_the_packed_blob_agrees_with_the_array_form(): void {
		$index  = RangeIndex::build( array( '10.0.0.0/24', '172.16.0.0/12', '203.0.113.0/29' ) );
		$packed = RangeIndex::pack_ranges( $index['v4'] );

		$this->assertSame( count( $index['v4'] ) * 8, strlen( $packed ) );

		foreach ( array( '9.255.255.255', '10.0.0.0', '10.0.0.255', '10.0.1.0',
			'172.15.255.255', '172.16.0.0', '172.31.255.255', '172.32.0.0',
			'203.0.113.0', '203.0.113.7', '203.0.113.8', '203.0.113.255' ) as $ip ) {

			$this->assertSame(
				RangeIndex::contains( $ip, $index['v4'] ),
				RangeIndex::packed_contains( $ip, $packed ),
				sprintf( '%s classified differently by the packed blob', $ip )
			);
		}
	}

	public function test_an_empty_blob_matches_nothing(): void {
		$this->assertFalse( RangeIndex::packed_contains( '10.0.0.1', '' ) );
	}

	/**
	 * Addresses above 127.255.255.255 are negative as signed 32-bit ints, which
	 * is exactly where a naive pack/unpack round trip breaks.
	 */
	public function test_high_addresses_round_trip_through_the_blob(): void {
		$index  = RangeIndex::build( array( '203.0.113.0/24', '255.255.255.0/24' ) );
		$packed = RangeIndex::pack_ranges( $index['v4'] );

		$this->assertTrue( RangeIndex::packed_contains( '203.0.113.7', $packed ) );
		$this->assertTrue( RangeIndex::packed_contains( '255.255.255.1', $packed ) );
		$this->assertFalse( RangeIndex::packed_contains( '204.0.113.7', $packed ) );
	}

	public function test_an_empty_feed_produces_an_empty_index(): void {
		$index = RangeIndex::build( array() );

		$this->assertSame( array(), $index['v4'] );
		$this->assertFalse( RangeIndex::contains( '10.0.0.1', $index['v4'] ) );
	}
}
