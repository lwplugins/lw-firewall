<?php
/**
 * Tests for which failed logins count against the IP.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rules\LoginTracker;
use LightweightPlugins\Firewall\Rules\UserLockGuard;
use LightweightPlugins\Firewall\Rules\UserLockout;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

require_once dirname( __DIR__ ) . '/Support/WpError.php';

/**
 * @covers \LightweightPlugins\Firewall\Rules\LoginTracker
 */
final class LoginTrackerTest extends MonkeyTestCase {

	/**
	 * Regression: a locked user retrying with the correct password fired
	 * wp_login_failed, the IP tracker counted it, and the administrator's own
	 * IP ended up banned site-wide.
	 */
	public function test_a_refusal_for_a_locked_username_does_not_count_against_the_ip(): void {
		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		Functions\stubTranslationFunctions();
		Functions\when( 'is_email' )->justReturn( false );
		Functions\when( 'get_user_by' )->justReturn( (object) array( 'user_login' => 'admin' ) );
		OptionStore::install( array( 'lw_firewall' => array( 'login_user_max_attempts' => 1 ) ) );
		$storage = new ArrayStorage();
		( new UserLockout( $storage ) )->record_failure( 'admin' );

		$refusal = ( new UserLockGuard( $storage ) )->authenticate( (object) array( 'ID' => 1 ), 'admin' );

		$this->assertFalse( LoginTracker::counts( $refusal ) );
	}

	public function test_a_wrong_password_still_counts(): void {
		$this->assertTrue( LoginTracker::counts( new \WP_Error( 'incorrect_password', 'x' ) ) );
	}

	public function test_a_failure_without_an_error_counts(): void {
		$this->assertTrue( LoginTracker::counts( null ) );
	}
}
