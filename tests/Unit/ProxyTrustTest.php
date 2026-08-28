<?php
/**
 * Tests for trusted reverse-proxy resolution.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use LightweightPlugins\Firewall\ProxyTrust;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\ProxyTrust
 */
final class ProxyTrustTest extends TestCase {

	protected function tearDown(): void {
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_FORWARDED'] );
		parent::tearDown();
	}

	/**
	 * Set the forwarded header for one assertion.
	 *
	 * @param string $value Header value.
	 */
	private function forwarded( string $value ): void {
		$_SERVER['HTTP_X_FORWARDED_FOR'] = $value;
	}

	/**
	 * The whole feature is opt-in: with no proxies listed, a forwarded header
	 * is just something the client sent and must never be believed.
	 */
	public function test_an_unconfigured_site_ignores_the_header(): void {
		$this->forwarded( '198.51.100.9' );

		$this->assertSame( '', ProxyTrust::resolve( '127.0.0.1', array(), 'x-forwarded-for' ) );
	}

	/**
	 * Even configured, only the listed hops may speak. A request arriving from
	 * somewhere else carries no authority over its own address.
	 */
	public function test_a_header_from_an_untrusted_hop_is_ignored(): void {
		$this->forwarded( '198.51.100.9' );

		$this->assertSame( '', ProxyTrust::resolve( '8.8.8.8', array( '127.0.0.1' ), 'x-forwarded-for' ) );
	}

	public function test_resolves_the_client_behind_a_local_proxy(): void {
		$this->forwarded( '198.51.100.9' );

		$this->assertSame( '198.51.100.9', ProxyTrust::resolve( '127.0.0.1', array( '127.0.0.1' ), 'x-forwarded-for' ) );
	}

	/**
	 * The chain is read right to left: hops we trust are skipped, and the first
	 * address we do not vouch for is the client. Everything further left was
	 * written by something outside our control.
	 */
	public function test_skips_trusted_hops_from_the_right(): void {
		$this->forwarded( '203.0.113.7, 198.51.100.9, 10.0.0.2' );

		$this->assertSame(
			'198.51.100.9',
			ProxyTrust::resolve( '10.0.0.1', array( '10.0.0.0/8' ), 'x-forwarded-for' )
		);
	}

	/**
	 * A client that prepends its own hop cannot promote that value: the
	 * rightmost untrusted entry still wins.
	 */
	public function test_a_spoofed_prefix_cannot_win(): void {
		$this->forwarded( '1.1.1.1, 203.0.113.7' );

		$this->assertSame(
			'203.0.113.7',
			ProxyTrust::resolve( '127.0.0.1', array( '127.0.0.1' ), 'x-forwarded-for' )
		);
	}

	public function test_returns_nothing_when_every_hop_is_trusted(): void {
		$this->forwarded( '10.0.0.5, 10.0.0.6' );

		$this->assertSame( '', ProxyTrust::resolve( '10.0.0.1', array( '10.0.0.0/8' ), 'x-forwarded-for' ) );
	}

	public function test_reads_the_nominated_header(): void {
		$_SERVER['HTTP_X_REAL_IP'] = '198.51.100.9';

		$this->assertSame( '198.51.100.9', ProxyTrust::resolve( '127.0.0.1', array( '127.0.0.1' ), 'x-real-ip' ) );
		$this->assertSame( '', ProxyTrust::resolve( '127.0.0.1', array( '127.0.0.1' ), 'x-forwarded-for' ) );
	}

	/**
	 * @dataProvider provide_header_shapes
	 *
	 * @param string $raw      Raw header value.
	 * @param array  $expected Addresses that should survive parsing.
	 */
	public function test_parses_real_world_header_shapes( string $raw, array $expected ): void {
		$this->assertSame( $expected, ProxyTrust::candidates( $raw ) );
	}

	/**
	 * @return array<string, array{0: string, 1: array<int, string>}>
	 */
	public static function provide_header_shapes(): array {
		return array(
			'plain list'      => array( '203.0.113.7, 198.51.100.9', array( '203.0.113.7', '198.51.100.9' ) ),
			'ipv4 with port'  => array( '203.0.113.7:51234', array( '203.0.113.7' ) ),
			'bracketed ipv6'  => array( '[2001:db8::1]:443', array( '2001:db8::1' ) ),
			'bare ipv6'       => array( '2001:db8::1', array( '2001:db8::1' ) ),
			'rfc 7239'        => array( 'for=203.0.113.7;proto=https', array( '203.0.113.7' ) ),
			'rfc 7239 quoted' => array( 'for="[2001:db8::1]:443"', array( '2001:db8::1' ) ),
			'junk dropped'    => array( 'unknown, 203.0.113.7, not-an-ip', array( '203.0.113.7' ) ),
			'empty'           => array( '', array() ),
		);
	}

	/**
	 * @dataProvider provide_non_routable
	 *
	 * @param string $ip       Address to classify.
	 * @param bool   $expected Whether it means "the real client is hidden".
	 */
	public function test_flags_addresses_that_mean_the_client_is_hidden( string $ip, bool $expected ): void {
		$this->assertSame( $expected, ProxyTrust::is_non_routable( $ip ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function provide_non_routable(): array {
		return array(
			'loopback'  => array( '127.0.0.1', true ),
			'ipv6 loop' => array( '::1', true ),
			'private'   => array( '10.0.0.5', true ),
			'private b' => array( '192.168.1.7', true ),
			'empty'     => array( '', true ),
			'garbage'   => array( 'not-an-ip', true ),
			// 203.0.113.0/24 and 2001:db8::/32 are documentation ranges, and PHP
			// disagrees between versions about whether they count as reserved —
			// so the routable cases use addresses that really are on the
			// internet.
			'public'    => array( '8.8.8.8', false ),
			'public v6' => array( '2606:4700:4700::1111', false ),
		);
	}
}
