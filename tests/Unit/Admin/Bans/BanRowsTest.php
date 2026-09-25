<?php
/**
 * Tests for the ban listing shape.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Bans;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Admin\Bans\BanRows;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Bans\BanRows
 * @covers \LightweightPlugins\Firewall\Admin\Bans\BanReasons
 */
final class BanRowsTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubTranslationFunctions();
	}

	/**
	 * @param string $ip      Index key.
	 * @param bool   $active  Enforced.
	 * @param int    $expires Expiry.
	 * @param string $reason  Reason.
	 * @return array{ip: string, expires: int, reason: string, time: int, active: bool}
	 */
	private static function row( string $ip, bool $active, int $expires, string $reason = 'login_lockout' ): array {
		return array(
			'ip'      => $ip,
			'expires' => $expires,
			'reason'  => $reason,
			'time'    => 900,
			'active'  => $active,
		);
	}

	public function test_summarises_enforced_tracked_and_expiring_bans(): void {
		$rows = array(
			self::row( '203.0.113.1', true, 1000 + 600 ),
			self::row( '203.0.113.2', true, 1000 + 7200 ),
			self::row( '203.0.113.3', false, 1000 + 60 ),
		);

		$this->assertSame(
			array(
				'total'         => 3,
				'enforced'      => 2,
				'tracked_only'  => 1,
				'expiring_soon' => 1,
			),
			BanRows::build( $rows, 1000 )['summary']
		);
	}

	public function test_labels_the_reason_and_names_the_source(): void {
		$item = BanRows::build( array( self::row( '203.0.113.1', true, 2000, 'reset_ip' ) ), 1000 )['items'][0];

		$this->assertSame( array( 'Password reset flood', 'password_reset' ), array( $item['reason_label'], $item['source'] ) );
	}

	public function test_an_unknown_reason_is_labelled_unknown(): void {
		$item = BanRows::build( array( self::row( '203.0.113.1', true, 2000, '' ) ), 1000 )['items'][0];

		$this->assertSame( array( 'Unknown', 'unknown' ), array( $item['reason_label'], $item['source'] ) );
	}

	/**
	 * @dataProvider provide_kinds
	 *
	 * @param string $ip       Index key.
	 * @param string $expected Kind.
	 */
	public function test_tells_networks_and_legacy_entries_apart( string $ip, string $expected ): void {
		$this->assertSame( $expected, BanRows::kind( $ip ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function provide_kinds(): array {
		return array(
			'ipv4'            => array( '203.0.113.9', 'ip' ),
			'ipv6 /64'        => array( '2a01:4f8:1:1::/64', 'network' ),
			'legacy ipv6 key' => array( '2a01:4f8:1:1::5', 'legacy' ),
		);
	}
}
