<?php
/**
 * Regression tests for client IP detection / Cloudflare trust.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use LightweightPlugins\Firewall\IpDetector;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\IpDetector
 */
final class IpDetectorTest extends TestCase {

	protected function tearDown(): void {
		unset( $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_CF_CONNECTING_IP'] );
		parent::tearDown();
	}

	public function test_uses_remote_addr_without_cloudflare(): void {
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';

		$this->assertSame( '203.0.113.9', IpDetector::get_ip() );
	}

	public function test_trusts_cf_connecting_ip_from_a_real_cloudflare_range(): void {
		$_SERVER['REMOTE_ADDR']           = '173.245.48.5'; // Within 173.245.48.0/20.
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.23';

		$this->assertSame( '198.51.100.23', IpDetector::get_ip() );
	}

	public function test_ignores_cf_connecting_ip_from_a_non_cloudflare_source(): void {
		$_SERVER['REMOTE_ADDR']           = '8.8.8.8';
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.23';

		$this->assertSame( '8.8.8.8', IpDetector::get_ip() );
	}

	/**
	 * A crafted IPv4 REMOTE_ADDR that shares the first 4 bytes of a Cloudflare
	 * IPv6 range (36.0.203.0 vs 2400:cb00::/32) must NOT be trusted as
	 * Cloudflare, so a spoofed CF-Connecting-IP is ignored.
	 */
	public function test_crafted_ipv4_cannot_spoof_via_ipv6_cloudflare_range(): void {
		$_SERVER['REMOTE_ADDR']           = '36.0.203.0';
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '6.6.6.6';

		$this->assertSame( '36.0.203.0', IpDetector::get_ip() );
	}
}
