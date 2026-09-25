<?php
/**
 * Tests for per-username login throttling.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rules\UserLockList;
use LightweightPlugins\Firewall\Rules\UserLockout;
use LightweightPlugins\Firewall\Rules\UsernameKey;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

/**
 * @covers \LightweightPlugins\Firewall\Rules\UserLockout
 * @covers \LightweightPlugins\Firewall\Rules\UserLockList
 * @covers \LightweightPlugins\Firewall\Rules\UsernameKey
 */
final class UserLockoutTest extends MonkeyTestCase {

	private ArrayStorage $storage;

	private OptionStore $options;

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		Functions\stubTranslationFunctions();
		$this->options = OptionStore::install(
			array(
				'lw_firewall' => array(
					'login_user_max_attempts'     => 3,
					'login_lockout_window'        => 600,
					'login_user_lockout_duration' => 900,
				),
			)
		);
		$this->storage = new ArrayStorage();
	}

	private function fail_times( string $login, int $times ): void {
		$lockout = new UserLockout( $this->storage );

		for ( $i = 0; $i < $times; $i++ ) {
			$lockout->record_failure( $login );
		}
	}

	public function test_locks_the_username_at_the_threshold(): void {
		$this->fail_times( 'admin', 3 );

		$this->assertTrue( ( new UserLockout( $this->storage ) )->is_locked( 'admin' ) );
	}

	public function test_does_not_lock_below_the_threshold(): void {
		$this->fail_times( 'admin', 2 );

		$this->assertFalse( ( new UserLockout( $this->storage ) )->is_locked( 'admin' ) );
	}

	/**
	 * The lock is per account, whoever asks: attempts from rotating IPs add up.
	 */
	public function test_the_username_is_normalised_before_counting(): void {
		$this->fail_times( 'Admin', 1 );
		$this->fail_times( ' admin ', 1 );
		$this->fail_times( 'ADMIN', 1 );

		$this->assertTrue( ( new UserLockout( $this->storage ) )->is_locked( 'admin' ) );
	}

	public function test_unknown_usernames_are_counted_too(): void {
		$this->fail_times( 'no-such-user', 3 );

		$this->assertTrue( ( new UserLockout( $this->storage ) )->is_locked( 'no-such-user' ) );
	}

	public function test_a_lock_is_listed_with_the_username(): void {
		$this->fail_times( 'Admin', 3 );

		$this->assertSame( array( 'Admin' ), array_column( UserLockList::all( $this->storage ), 'user' ) );
	}

	public function test_unlocking_lifts_the_lock_and_clears_the_count(): void {
		$this->fail_times( 'admin', 3 );
		$lockout = new UserLockout( $this->storage );

		$lockout->unlock( UsernameKey::hash( 'admin' ) );
		$lockout->record_failure( 'admin' );

		$this->assertFalse( $lockout->is_locked( 'admin' ) );
	}

	public function test_unlocking_removes_the_list_entry(): void {
		$this->fail_times( 'admin', 3 );

		( new UserLockout( $this->storage ) )->unlock( UsernameKey::hash( 'admin' ) );

		$this->assertSame( array(), UserLockList::all( $this->storage ) );
	}

	public function test_an_empty_username_is_never_counted(): void {
		$this->fail_times( '  ', 5 );

		$this->assertSame( array(), UserLockList::all( $this->storage ) );
	}

	/**
	 * @dataProvider provide_logins
	 *
	 * @param string $raw      Typed login.
	 * @param string $expected Normalised form.
	 */
	public function test_normalises_a_login( string $raw, string $expected ): void {
		$this->assertSame( $expected, UsernameKey::normalize( $raw ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function provide_logins(): array {
		return array(
			'case'        => array( 'AdMin', 'admin' ),
			'spaces'      => array( "  admin\t", 'admin' ),
			'inner space' => array( 'john   doe', 'john doe' ),
			'email'       => array( 'John@Example.COM', 'john@example.com' ),
			'empty'       => array( '   ', '' ),
		);
	}

	public function test_the_lock_index_is_capped(): void {
		$entries = array();

		for ( $i = 0; $i < UserLockList::MAX_ENTRIES + 5; $i++ ) {
			$entries[ 'k' . $i ] = array(
				'user'    => 'u' . $i,
				'expires' => 5000,
				'time'    => $i,
			);
		}

		$this->assertCount( UserLockList::MAX_ENTRIES, UserLockList::prune( $entries, 1000 ) );
	}

	public function test_expired_locks_are_pruned(): void {
		$pruned = UserLockList::prune(
			array(
				'a' => array( 'user' => 'a', 'expires' => 999, 'time' => 1 ),
				'b' => array( 'user' => 'b', 'expires' => 2000, 'time' => 1 ),
			),
			1000
		);

		$this->assertSame( array( 'b' ), array_keys( $pruned ) );
	}
}
