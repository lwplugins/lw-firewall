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
		Functions\when( 'is_email' )->alias( static fn ( string $e ) => false !== filter_var( $e, FILTER_VALIDATE_EMAIL ) ? $e : false );
		Functions\when( 'get_user_by' )->alias(
			static fn ( string $field, string $value ) => ( 'email' === $field && 'admin@example.com' === $value ) || ( 'login' === $field && 'admin' === strtolower( $value ) )
				? (object) array( 'user_login' => 'admin' )
				: false
		);
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

	/**
	 * Regression: unlocking by email reported success while the lock stayed.
	 */
	public function test_unlocking_by_email_lifts_the_accounts_lock(): void {
		( new UserUnlocker( $this->lockout ) )->unlock( array( 'admin@example.com' ) );

		$this->assertFalse( $this->lockout->is_locked( 'admin' ) );
	}

	/**
	 * Regression: a typo reported "Username unlocked" although nothing was.
	 */
	public function test_unlocking_a_username_that_is_not_locked_says_so(): void {
		$result = ( new UserUnlocker( $this->lockout ) )->unlock( array( 'admn' ) )[0];

		$this->assertSame( array( false, 'This username is not locked.' ), array( $result['ok'], $result['message'] ) );
	}
}
