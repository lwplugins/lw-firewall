<?php
/**
 * Tests for the IP → counting/ban subject mapping.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use LightweightPlugins\Firewall\IpSubject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\IpSubject
 */
final class IpSubjectTest extends TestCase {

	/**
	 * @dataProvider provide_addresses
	 *
	 * @param string $ip       Client address.
	 * @param string $expected Subject key.
	 */
	public function test_maps_an_address_to_its_subject( string $ip, string $expected ): void {
		$this->assertSame( $expected, IpSubject::of( $ip ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function provide_addresses(): array {
		return [
			'IPv4 unchanged'                  => [ '203.0.113.7', '203.0.113.7' ],
			'IPv6 host collapses to its /64'  => [ '2001:db8:1:1::1', '2001:db8:1:1::/64' ],
			'IPv6 full notation, upper case'  => [ '2001:0DB8:0001:0001:ABCD:0000:0000:0001', '2001:db8:1:1::/64' ],
			'IPv6 /64 key is idempotent'      => [ '2001:db8:1:1::/64', '2001:db8:1:1::/64' ],
			'non-canonical /64 key'           => [ '2001:DB8:1:1:ffff::/64', '2001:db8:1:1::/64' ],
			'IPv4-mapped IPv6 becomes IPv4'   => [ '::ffff:203.0.113.7', '203.0.113.7' ],
			'unparseable input is left alone' => [ 'not-an-ip', 'not-an-ip' ],
		];
	}

	public function test_two_addresses_in_one_slash_64_share_a_subject(): void {
		$this->assertSame( IpSubject::of( '2001:db8:aa:bb::1' ), IpSubject::of( '2001:db8:aa:bb:dead:beef:0:42' ) );
	}

	public function test_neighbouring_slash_64s_do_not_share_a_subject(): void {
		$this->assertNotSame( IpSubject::of( '2001:db8:aa:bb::1' ), IpSubject::of( '2001:db8:aa:bc::1' ) );
	}

	/**
	 * @dataProvider provide_mapped
	 *
	 * @param string $ip       Address.
	 * @param string $expected Unmapped address.
	 */
	public function test_unmaps_ipv4_mapped_addresses( string $ip, string $expected ): void {
		$this->assertSame( $expected, IpSubject::unmap( $ip ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function provide_mapped(): array {
		return [
			'mapped'       => [ '::ffff:10.0.0.1', '10.0.0.1' ],
			'plain IPv4'   => [ '10.0.0.1', '10.0.0.1' ],
			'plain IPv6'   => [ '2001:db8::1', '2001:db8::1' ],
			'not an IP'    => [ 'x', 'x' ],
		];
	}

	/**
	 * @dataProvider provide_targets
	 *
	 * @param string $input    Operator input (admin, CLI).
	 * @param string $expected Parsed subject, or '' when invalid.
	 */
	public function test_parses_an_operator_supplied_target( string $input, string $expected ): void {
		$this->assertSame( $expected, IpSubject::parse( $input ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function provide_targets(): array {
		return [
			'IPv4'                  => [ ' 198.51.100.1 ', '198.51.100.1' ],
			'IPv6 host'             => [ '2001:db8::5', '2001:db8::/64' ],
			'IPv6 /64 key'          => [ '2001:db8:0:0::/64', '2001:db8::/64' ],
			'other IPv6 prefix'     => [ '2001:db8::/48', '' ],
			'IPv4 with /64'         => [ '198.51.100.1/64', '' ],
			'garbage'               => [ 'hello', '' ],
			'empty'                 => [ '', '' ],
		];
	}
}
