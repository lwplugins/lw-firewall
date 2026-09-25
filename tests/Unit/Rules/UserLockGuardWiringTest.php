<?php
/**
 * Tests for the per-username lockout hook callbacks.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rules\LoginResolver;
use LightweightPlugins\Firewall\Rules\UserLockGuard;
use LightweightPlugins\Firewall\Rules\UserLockout;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

require_once dirname( __DIR__ ) . '/Support/WpError.php';

/**
 * @covers \LightweightPlugins\Firewall\Rules\UserLockGuard
 * @covers \LightweightPlugins\Firewall\Rules\LoginResolver
 */
final class UserLockGuardWiringTest extends MonkeyTestCase {

	private ArrayStorage $storage;

	/**
	 * Server variables before the test.
	 *
	 * @var array<string, mixed>
	 */
	private array $server = array();

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		$this->server           = $_SERVER;
		$_SERVER['REMOTE_ADDR'] = '8.8.8.8';

		Functions\stubTranslationFunctions();
		Functions\when( 'is_email' )->alias( static fn ( string $e ) => false !== filter_var( $e, FILTER_VALIDATE_EMAIL ) ? $e : false );

		// The site has one account, "admin" (admin@example.com). Like
		// WordPress with a *_unicode_ci collation, a full-width or
		// zero-width variant of the login resolves to it.
		Functions\when( 'get_user_by' )->alias(
			static function ( string $field, string $value ) {
				$admin = (object) array( 'user_login' => 'admin' );

				if ( 'email' === $field ) {
					return 'admin@example.com' === strtolower( $value ) ? $admin : false;
				}

				$folded = strtolower( str_replace( array( "\u{200B}", "\u{FF41}" ), array( '', 'a' ), $value ) );

				return 'admin' === $folded ? $admin : false;
			}
		);

		$this->storage = new ArrayStorage();
	}

	protected function tearDown(): void {
		$_SERVER = $this->server;
		parent::tearDown();
	}

	/**
	 * @param array<string, mixed> $settings Stored settings.
	 * @return UserLockGuard
	 */
	private function guard( array $settings = array() ): UserLockGuard {
		OptionStore::install( array( 'lw_firewall' => array_merge( array( 'login_user_max_attempts' => 2 ), $settings ) ) );

		return new UserLockGuard( $this->storage );
	}

	private function locked( string $login ): bool {
		return ( new UserLockout( $this->storage ) )->is_locked( $login );
	}

	/**
	 * Regression: failures were keyed by the typed login, so each Unicode
	 * variant that WordPress still resolves to "admin" got a fresh counter.
	 */
	public function test_unicode_variants_of_a_login_share_the_accounts_counter(): void {
		$guard = $this->guard();

		$guard->on_failed( "a\u{200B}dmin" );
		$guard->on_failed( "\u{FF41}dmin" );

		$this->assertTrue( $this->locked( 'admin' ) );
	}

	public function test_an_email_login_counts_for_the_account(): void {
		$guard = $this->guard();

		$guard->on_failed( 'admin@example.com' );
		$guard->on_failed( 'Admin@Example.com' );

		$this->assertTrue( $this->locked( 'admin' ) );
	}

	public function test_a_variant_is_refused_while_the_account_is_locked(): void {
		$guard = $this->guard();
		$guard->on_failed( 'admin' );
		$guard->on_failed( 'admin' );

		$result = $guard->authenticate( (object) array( 'ID' => 1 ), "\u{FF41}dmin" );

		$this->assertSame( UserLockGuard::ERROR_CODE, $result->get_error_code() );
	}

	public function test_an_unlocked_account_passes_through(): void {
		$user = (object) array( 'ID' => 1 );

		$this->assertSame( $user, $this->guard()->authenticate( $user, 'admin' ) );
	}

	public function test_a_whitelisted_ip_is_not_counted(): void {
		$guard = $this->guard( array( 'ip_whitelist' => array( '8.8.8.8' ) ) );

		$guard->on_failed( 'admin' );
		$guard->on_failed( 'admin' );

		$this->assertFalse( $this->locked( 'admin' ) );
	}

	public function test_failures_on_a_locked_account_do_not_extend_the_lock(): void {
		$guard = $this->guard();
		$guard->on_failed( 'admin' );
		$guard->on_failed( 'admin' );
		$this->storage->delete( UserLockout::LOCK_PREFIX . md5( 'admin' ) );
		$this->storage->set( UserLockout::LOCK_PREFIX . md5( 'admin' ), 1, 900 );

		$guard->on_failed( 'admin' );

		$this->assertNull( $this->storage->get( UserLockout::COUNT_PREFIX . md5( 'admin' ) ) );
	}

	public function test_an_unknown_login_falls_back_to_the_typed_string(): void {
		$this->assertSame( 'nobody', LoginResolver::resolve( ' nobody ' ) );
	}
}
