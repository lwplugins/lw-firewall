<?php
/**
 * Tests for the packed IPv6 country range index.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Geo;

use LightweightPlugins\Firewall\Geo\RangeIndex6;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Geo\RangeIndex6
 */
final class RangeIndex6Test extends TestCase {

	/**
	 * The feed's own notation: fully expanded, zero padded.
	 */
	private const FEED = [
		'2001:0250:0000:0000:0000:0000:0000:0000/30',
		'2001:0db8:0000:0000:0000:0000:0000:0000/32',
		'2400:cb00::/32',
	];

	/**
	 * @dataProvider provide_lookups
	 *
	 * @param string $ip       Address to look up.
	 * @param bool   $expected Whether it is inside the feed.
	 */
	public function test_finds_addresses_inside_the_ranges( string $ip, bool $expected ): void {
		$this->assertSame( $expected, RangeIndex6::contains( $ip, RangeIndex6::build( self::FEED ) ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function provide_lookups(): array {
		return [
			'first address of a range'  => [ '2001:250::', true ],
			'last address of a /30'     => [ '2001:253:ffff:ffff:ffff:ffff:ffff:ffff', true ],
			'just past a /30'           => [ '2001:254::', false ],
			'inside the middle range'   => [ '2001:db8:1:1::1', true ],
			'inside the last range'     => [ '2400:cb00:abcd::1', true ],
			'before every range'        => [ '2000::1', false ],
			'after every range'         => [ 'fe80::1', false ],
			'IPv4 is never an IPv6 hit' => [ '32.1.2.80', false ],
			'garbage'                   => [ 'nope', false ],
		];
	}

	public function test_overlapping_ranges_are_merged(): void {
		$packed = RangeIndex6::build( [ '2001:db8::/32', '2001:db8:1::/48', '2001:db8::/33' ] );

		$this->assertSame( 32, strlen( $packed ) );
	}

	public function test_invalid_lines_are_skipped(): void {
		$packed = RangeIndex6::build( [ '10.0.0.0/8', '2001:db8::/129', '2001:db8::/x', 'junk', '2001:db8::/32' ] );

		$this->assertSame( 32, strlen( $packed ) );
	}

	public function test_an_empty_index_contains_nothing(): void {
		$this->assertFalse( RangeIndex6::contains( '2001:db8::1', RangeIndex6::build( [] ) ) );
	}
}
