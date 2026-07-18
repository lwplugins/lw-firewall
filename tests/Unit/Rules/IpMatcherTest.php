<?php
/**
 * Regression tests for IP / CIDR matching (whitelist / blacklist).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\IpMatcher;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\IpMatcher
 */
final class IpMatcherTest extends TestCase {

	public function test_matches_exact_ipv4(): void {
		$this->assertTrue( IpMatcher::matches( '203.0.113.7', array( '203.0.113.7' ) ) );
	}

	public function test_matches_ipv4_cidr(): void {
		$this->assertTrue( IpMatcher::matches( '10.1.2.3', array( '10.0.0.0/8' ) ) );
		$this->assertFalse( IpMatcher::matches( '11.1.2.3', array( '10.0.0.0/8' ) ) );
	}

	public function test_matches_cidr_with_a_non_byte_aligned_prefix(): void {
		// /28 exercises the partial last-byte mask.
		$this->assertTrue( IpMatcher::matches( '192.168.1.5', array( '192.168.1.0/28' ) ) );
		$this->assertFalse( IpMatcher::matches( '192.168.1.20', array( '192.168.1.0/28' ) ) );
	}

	public function test_empty_list_never_matches(): void {
		$this->assertFalse( IpMatcher::matches( '203.0.113.7', array() ) );
		$this->assertFalse( IpMatcher::matches( '203.0.113.7', array( '', '   ' ) ) );
	}

	/**
	 * An IPv4 client must never match an IPv6 CIDR entry (family mismatch).
	 * 32.1.13.184 shares the first 4 bytes of 2001:db8::/32.
	 */
	public function test_ipv4_does_not_match_ipv6_cidr(): void {
		$this->assertFalse( IpMatcher::matches( '32.1.13.184', array( '2001:db8::/32' ) ) );
	}

	public function test_ipv6_does_not_match_ipv4_cidr(): void {
		$this->assertFalse( IpMatcher::matches( '2001:db8::1', array( '10.0.0.0/8' ) ) );
	}

	public function test_ipv6_matches_its_own_cidr(): void {
		$this->assertTrue( IpMatcher::matches( '2001:db8::abcd', array( '2001:db8::/32' ) ) );
	}

	/**
	 * The same IPv6 address written in a different (uppercase, expanded)
	 * notation must still match — exact matching compares canonical bytes.
	 */
	public function test_ipv6_exact_match_ignores_notation(): void {
		$this->assertTrue(
			IpMatcher::matches( '2001:db8::1', array( '2001:DB8:0:0:0:0:0:1' ) )
		);
	}
}
