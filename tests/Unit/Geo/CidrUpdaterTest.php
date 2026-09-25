<?php
/**
 * Tests for turning downloaded country feeds into cache files.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Geo;

use LightweightPlugins\Firewall\Geo\CidrUpdater;
use LightweightPlugins\Firewall\Geo\RangeIndex;
use LightweightPlugins\Firewall\Geo\RangeIndex6;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Geo\CidrUpdater
 */
final class CidrUpdaterTest extends TestCase {

	public function test_parses_a_zone_body_into_lines(): void {
		$this->assertSame(
			[ '1.0.1.0/24', '2001:db8::/32' ],
			CidrUpdater::parse_zone( "1.0.1.0/24\r\n\n  2001:db8::/32  \n" )
		);
	}

	/**
	 * The bug: only the IPv4 feed was used, so without Cloudflare an IPv6
	 * visitor from a blocked country was never matched.
	 */
	public function test_the_ipv6_feed_becomes_a_searchable_ipv6_index(): void {
		$files = CidrUpdater::cache_files( [ '1.0.1.0/24' ], [ '2001:db8::/32' ] );

		$this->assertTrue( RangeIndex6::contains( '2001:db8:5::1', $files['v6.bin'] ) );
	}

	public function test_the_ipv4_feed_becomes_a_searchable_ipv4_index(): void {
		$files = CidrUpdater::cache_files( [ '1.0.1.0/24' ], [ '2001:db8::/32' ] );

		$this->assertTrue( RangeIndex::packed_contains( '1.0.1.9', $files['bin'] ) );
	}

	/**
	 * A failed IPv6 download must not cost the country its IPv4 ranges — and
	 * must not overwrite the previous IPv6 index with an empty one either.
	 */
	public function test_a_failed_ipv6_download_keeps_the_ipv4_result(): void {
		$files = CidrUpdater::cache_files( [ '1.0.1.0/24' ], null );

		$this->assertSame( [ 'bin', 'php' ], array_keys( $files ) );
	}

	public function test_a_failed_ipv4_download_keeps_the_ipv6_result(): void {
		$files = CidrUpdater::cache_files( null, [ '2001:db8::/32' ] );

		$this->assertSame( [ 'v6.bin', 'php' ], array_keys( $files ) );
	}

	public function test_the_metadata_file_is_a_marked_php_return(): void {
		$files = CidrUpdater::cache_files( [ '1.0.1.0/24' ], [ '2001:db8::/32' ] );

		$this->assertStringStartsWith( "<?php\nreturn ", $files['php'] );
		$this->assertStringContainsString( RangeIndex::FORMAT, $files['php'] );
	}
}
