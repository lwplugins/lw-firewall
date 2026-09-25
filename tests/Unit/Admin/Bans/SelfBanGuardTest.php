<?php
/**
 * Tests for the "do not ban yourself" guard.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Bans;

use LightweightPlugins\Firewall\Admin\Bans\SelfBanGuard;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Bans\SelfBanGuard
 */
final class SelfBanGuardTest extends TestCase {

	/**
	 * Regression: POST /admin/bans let the administrator ban the address
	 * they were using, which the worker then blocked site-wide, wp-admin
	 * included.
	 *
	 * @dataProvider provide_own_addresses
	 *
	 * @param string $target  Requested ban.
	 * @param string $current The administrator's resolved address.
	 */
	public function test_recognises_the_administrators_own_address( string $target, string $current ): void {
		$this->assertTrue( SelfBanGuard::is_own_address( $target, $current ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function provide_own_addresses(): array {
		return array(
			'same ipv4'           => array( '203.0.113.7', '203.0.113.7' ),
			'same ipv6 /64'       => array( '2a01:4f8:1:1::99', '2a01:4f8:1:1::1' ),
			'the /64 subject key' => array( '2a01:4f8:1:1::/64', '2a01:4f8:1:1::1' ),
		);
	}

	public function test_another_address_is_not_own(): void {
		$this->assertFalse( SelfBanGuard::is_own_address( '203.0.113.8', '203.0.113.7' ) );
	}
}
