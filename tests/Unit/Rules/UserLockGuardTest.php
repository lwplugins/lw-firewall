<?php
/**
 * Tests for the per-username lockout decisions.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Admin\Bans\UserUnlocker;
use LightweightPlugins\Firewall\Rules\UserLockGuard;
use LightweightPlugins\Firewall\Rules\UserLockout;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

/**
 * @covers \LightweightPlugins\Firewall\Rules\UserLockGuard
 * @covers \LightweightPlugins\Firewall\Admin\Bans\UserUnlocker
 */
final class UserLockGuardTest extends MonkeyTestCase {

	private UserLockout $lockout;

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		Functions\stubTranslationFunctions();
		OptionStore::install( array( 'lw_firewall' => array( 'login_user_max_attempts' => 1 ) ) );
		$this->lockout = new UserLockout( new ArrayStorage() );
		$this->lockout->record_failure( 'admin' );
	}

	/**
	 * A lockout, not a delay: the right password does not get through.
	 */
	public function test_a_locked_username_is_refused(): void {
		$this->assertTrue( UserLockGuard::should_refuse( 'admin', $this->lockout, false ) );
	}

	public function test_a_whitelisted_ip_is_never_refused(): void {
		$this->assertFalse( UserLockGuard::should_refuse( 'admin', $this->lockout, true ) );
	}

	public function test_another_username_is_not_refused(): void {
		$this->assertFalse( UserLockGuard::should_refuse( 'editor', $this->lockout, false ) );
	}

	public function test_an_administrator_can_unlock_by_username(): void {
		$results = ( new UserUnlocker( $this->lockout ) )->unlock( array( 'Admin' ) );

		$this->assertSame( array( true, 'admin' ), array( $results[0]['ok'], $results[0]['user'] ) );
	}

	public function test_unlock_all_lifts_every_lock(): void {
		( new UserUnlocker( $this->lockout ) )->unlock_all();

		$this->assertFalse( $this->lockout->is_locked( 'admin' ) );
	}
}
