<?php
/**
 * Tests for the guard that keeps shared/proxy addresses out of counting and bans.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\AutoBanner;
use LightweightPlugins\Firewall\Rules\CountGuard;
use LightweightPlugins\Firewall\Rules\LoginTracker;
use LightweightPlugins\Firewall\Rules\NotFoundTracker;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

/**
 * @covers \LightweightPlugins\Firewall\Rules\CountGuard
 */
final class CountGuardTest extends MonkeyTestCase {

	private const PROXIES = [ '198.51.100.10', '2001:db8:ffff::/48' ];

	private ArrayStorage $storage;

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		OptionStore::install(
			[
				'lw_firewall' => [
					'login_max_attempts' => 1,
					'rate_limit'         => 0,
					'trusted_proxies'    => self::PROXIES,
					'log_enabled'        => false,
				],
			]
		);

		$this->storage = new ArrayStorage();
	}

	protected function tearDown(): void {
		unset( $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR'] );
		parent::tearDown();
	}

	/**
	 * @dataProvider provide_addresses
	 *
	 * @param string $ip       Resolved client address.
	 * @param bool   $expected Whether it may be counted and banned.
	 */
	public function test_decides_whether_an_address_may_be_counted( string $ip, bool $expected ): void {
		$this->assertSame( $expected, CountGuard::allows_for( $ip, self::PROXIES ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function provide_addresses(): array {
		return [
			'public IPv4'                 => [ '8.8.8.8', true ],
			'public IPv6'                 => [ '2a01:4f8::1', true ],
			'public IPv4-mapped IPv6'     => [ '::ffff:8.8.8.8', true ],
			'private 10/8'                => [ '10.1.2.3', false ],
			'private 172.16/12'           => [ '172.20.0.1', false ],
			'private 192.168/16'          => [ '192.168.1.1', false ],
			'carrier-grade NAT 100.64/10' => [ '100.64.0.1', false ],
			'loopback IPv4'               => [ '127.0.0.1', false ],
			'loopback IPv6'               => [ '::1', false ],
			'link-local IPv4'             => [ '169.254.10.1', false ],
			'link-local IPv6'             => [ 'fe80::1', false ],
			'unique-local IPv6'           => [ 'fd00::1', false ],
			'private IPv4-mapped IPv6'    => [ '::ffff:10.0.0.1', false ],
			'unspecified (detector miss)' => [ '0.0.0.0', false ],
			'trusted proxy, exact'        => [ '198.51.100.10', false ],
			'trusted proxy, CIDR'         => [ '2001:db8:ffff:1::1', false ],
			'next to the trusted proxy'   => [ '198.51.100.11', true ],
			'empty'                       => [ '', false ],
		];
	}

	/**
	 * The lockout: behind an unconfigured proxy every visitor is 10.0.0.1, so a
	 * few failed logins banned the whole site, administrators included.
	 */
	public function test_failed_logins_from_a_private_address_never_ban_it(): void {
		$_SERVER['REMOTE_ADDR'] = '10.0.0.1';

		( new LoginTracker( $this->storage ) )->record_failure();

		$this->assertFalse( ( new AutoBanner( $this->storage ) )->is_banned( '10.0.0.1' ) );
	}

	/**
	 * A configured proxy whose forwarded header is missing: IpDetector falls
	 * back to the proxy's own address, which must not be charged.
	 */
	public function test_a_trusted_proxy_without_a_forwarded_header_is_not_charged(): void {
		$_SERVER['REMOTE_ADDR'] = '198.51.100.10';

		( new LoginTracker( $this->storage ) )->record_failure();

		$this->assertFalse( ( new AutoBanner( $this->storage ) )->is_banned( '198.51.100.10' ) );
	}

	public function test_the_forwarded_client_behind_a_trusted_proxy_is_still_charged(): void {
		$_SERVER['REMOTE_ADDR']          = '198.51.100.10';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '8.8.4.4';

		( new LoginTracker( $this->storage ) )->record_failure();

		$this->assertTrue( ( new AutoBanner( $this->storage ) )->is_banned( '8.8.4.4' ) );
	}

	public function test_a_private_address_is_never_banned_directly(): void {
		( new AutoBanner( $this->storage ) )->ban( '192.168.1.1', 600, 'reset_ip' );

		$this->assertFalse( ( new AutoBanner( $this->storage ) )->is_banned( '192.168.1.1' ) );
	}

	public function test_404s_from_a_private_address_are_not_a_flood(): void {
		$_SERVER['REMOTE_ADDR'] = '10.0.0.1';
		$tracker                = new NotFoundTracker( $this->storage );

		$tracker->record();

		$this->assertFalse( $tracker->is_flooding( '10.0.0.1' ) );
	}
}
