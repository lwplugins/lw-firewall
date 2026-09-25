<?php
/**
 * Tests that the per-client trackers count IPv6 clients per /64.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\AutoBanner;
use LightweightPlugins\Firewall\Rules\LoginTracker;
use LightweightPlugins\Firewall\Rules\NotFoundTracker;
use LightweightPlugins\Firewall\Rules\RegisterTracker;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

/**
 * @covers \LightweightPlugins\Firewall\Rules\LoginTracker
 * @covers \LightweightPlugins\Firewall\Rules\RegisterTracker
 * @covers \LightweightPlugins\Firewall\Rules\NotFoundTracker
 */
final class TrackerSubjectTest extends MonkeyTestCase {

	private ArrayStorage $storage;

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		OptionStore::install(
			[
				'lw_firewall' => [
					'login_max_attempts'     => 2,
					'register_ban_threshold' => 2,
					'rate_limit'             => 1,
					'log_enabled'            => false,
				],
			]
		);

		$this->storage = new ArrayStorage();
	}

	protected function tearDown(): void {
		unset( $_SERVER['REMOTE_ADDR'] );
		parent::tearDown();
	}

	/**
	 * Run a callback as if the request came from the given address.
	 *
	 * @param string   $ip       Client address.
	 * @param callable $callback Work to do.
	 * @return void
	 */
	private static function from( string $ip, callable $callback ): void {
		$_SERVER['REMOTE_ADDR'] = $ip;
		$callback();
	}

	public function test_failed_logins_from_one_slash_64_add_up_to_a_ban(): void {
		$tracker = new LoginTracker( $this->storage );

		self::from( '2a01:4f8:1:1::a', [ $tracker, 'record_failure' ] );
		self::from( '2a01:4f8:1:1::b', [ $tracker, 'record_failure' ] );

		$this->assertTrue( ( new AutoBanner( $this->storage ) )->is_banned( '2a01:4f8:1:1::c' ) );
	}

	public function test_failed_logins_from_different_slash_64s_are_counted_apart(): void {
		$tracker = new LoginTracker( $this->storage );

		self::from( '2a01:4f8:1:1::a', [ $tracker, 'record_failure' ] );
		self::from( '2a01:4f8:1:2::a', [ $tracker, 'record_failure' ] );

		$this->assertFalse( ( new AutoBanner( $this->storage ) )->is_banned( '2a01:4f8:1:2::a' ) );
	}

	public function test_failed_logins_from_neighbouring_ipv4_addresses_are_counted_apart(): void {
		$tracker = new LoginTracker( $this->storage );

		self::from( '203.0.113.7', [ $tracker, 'record_failure' ] );
		self::from( '203.0.113.8', [ $tracker, 'record_failure' ] );

		$this->assertFalse( ( new AutoBanner( $this->storage ) )->is_banned( '203.0.113.8' ) );
	}

	public function test_rejected_registrations_from_one_slash_64_add_up_to_a_ban(): void {
		$tracker = new RegisterTracker( $this->storage );

		self::from( '2a01:4f8:1:1::a', [ $tracker, 'record' ] );
		self::from( '2a01:4f8:1:1::b', [ $tracker, 'record' ] );

		$this->assertTrue( ( new AutoBanner( $this->storage ) )->is_banned( '2a01:4f8:1:1::c' ) );
	}

	public function test_404s_from_one_slash_64_add_up_to_a_flood(): void {
		$tracker = new NotFoundTracker( $this->storage );

		self::from( '2a01:4f8:1:1::a', [ $tracker, 'record' ] );
		self::from( '2a01:4f8:1:1::b', [ $tracker, 'record' ] );

		$this->assertTrue( $tracker->is_flooding( '2a01:4f8:1:1::c' ) );
	}
}
