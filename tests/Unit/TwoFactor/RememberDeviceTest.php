<?php
/**
 * Tests for the trusted-device cookie.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\TwoFactor\RememberDevice;
use LightweightPlugins\Firewall\TwoFactor\RememberRevoker;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\RememberDevice
 * @covers \LightweightPlugins\Firewall\TwoFactor\RememberRevoker
 */
final class RememberDeviceTest extends MonkeyTestCase {

	use UserMetaStubTrait;

	private int $now = 1700000000;

	/**
	 * Captured cookies.
	 *
	 * @var array<int, array{0: string, 1: string, 2: array<string, mixed>}>
	 */
	private array $sink = array();

	protected function setUp(): void {
		parent::setUp();
		if ( ! defined( 'DAY_IN_SECONDS' ) ) {
			define( 'DAY_IN_SECONDS', 86400 );
		}
		$this->stub_user_meta();
		require_once dirname( __DIR__ ) . '/Support/WpUser.php';
		OptionStore::install( array( 'lw_firewall' => array( 'twofa_remember_days' => 30 ) ) );
		Functions\when( 'wp_salt' )->justReturn( 'salt-one' );
		Functions\when( 'wp_unslash' )->alias( static fn ( $v ) => is_string( $v ) ? stripslashes( $v ) : $v );
		Functions\when( 'is_ssl' )->justReturn( true );
		$_COOKIE    = array();
		$this->sink = array();
	}

	protected function tearDown(): void {
		$_COOKIE = array();
		parent::tearDown();
	}

	private function device(): RememberDevice {
		return new RememberDevice(
			fn (): int => $this->now,
			function ( string $name, string $value, array $options ): void {
				$this->sink[] = array( $name, $value, $options );
			}
		);
	}

	private function issue_and_carry( int $user_id = 5 ): string {
		$this->device()->issue( $user_id, 30 );
		$_COOKIE[ $this->sink[0][0] ] = $this->sink[0][1];

		return $this->sink[0][1];
	}

	public function test_issued_cookie_is_valid_and_has_the_expected_attributes(): void {
		$value = $this->issue_and_carry();

		$this->assertTrue( $this->device()->is_valid( 5 ) );
		$this->assertMatchesRegularExpression( '/^5\|' . $this->now . '\|' . ( $this->now + 30 * 86400 ) . '\|[0-9a-f]{64}$/', $value );
		$o = $this->sink[0][2];
		$this->assertSame( $this->now + 30 * 86400, $o['expires'] );
		$this->assertSame( '/', $o['path'] );
		$this->assertTrue( $o['secure'] );
		$this->assertTrue( $o['httponly'] );
		$this->assertSame( 'Lax', $o['samesite'] );
		$this->assertStringStartsWith( 'lwfw_2fa_rd_', $this->sink[0][0] );
	}

	public function test_no_cookie_is_invalid(): void {
		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_expired_cookie_is_invalid(): void {
		$this->issue_and_carry();
		$this->now += 30 * 86400;

		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_other_user_is_invalid(): void {
		$this->issue_and_carry( 5 );

		$this->assertFalse( $this->device()->is_valid( 6 ) );
	}

	public function test_tampered_hmac_user_or_expiry_is_invalid(): void {
		$value = $this->issue_and_carry();
		list( $uid, $iss, $exp, $mac ) = explode( '|', $value );
		$name = $this->sink[0][0];

		foreach ( array(
			$uid . '|' . $iss . '|' . $exp . '|' . strrev( $mac ),
			$uid . '|' . $iss . '|' . ( (int) $exp + 86400 ) . '|' . $mac,
			$uid . '|' . ( (int) $iss - 86400 ) . '|' . $exp . '|' . $mac,
			'6|' . $iss . '|' . $exp . '|' . $mac,
			$value . '|x',
			$uid . '|' . $exp . '|' . $mac,
			$uid . '|' . $iss . '|abc|' . $mac,
			'-5|' . $iss . '|' . $exp . '|' . $mac,
		) as $bad ) {
			$_COOKIE[ $name ] = $bad;
			$this->assertFalse( $this->device()->is_valid( 5 ), $bad );
		}
		$_COOKIE[ $name ] = array( 'x' );
		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_reset_all_rotates_the_salt_and_invalidates(): void {
		$this->issue_and_carry();
		$this->assertTrue( $this->device()->is_valid( 5 ) );

		( new UserFactors( 5 ) )->reset_all();

		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_zero_days_ignores_existing_cookies_and_issues_nothing(): void {
		$this->issue_and_carry();
		OptionStore::install( array( 'lw_firewall' => array( 'twofa_remember_days' => 0 ) ) );

		$this->assertFalse( $this->device()->is_valid( 5 ) );
		$this->sink = array();
		$this->device()->issue( 5, 0 );
		$this->assertSame( array(), $this->sink );
	}

	public function test_lowering_the_lifetime_shortens_existing_cookies(): void {
		$this->issue_and_carry();
		$this->now += 10 * 86400;
		$this->assertTrue( $this->device()->is_valid( 5 ) );

		OptionStore::install( array( 'lw_firewall' => array( 'twofa_remember_days' => 7 ) ) );

		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_a_cookie_issued_in_the_future_is_rejected(): void {
		$this->issue_and_carry();
		$this->now -= 3600;

		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_forget_devices_invalidates(): void {
		$this->issue_and_carry();
		( new UserFactors( 5 ) )->forget_devices();

		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_revoker_registers_its_hooks(): void {
		Actions\expectAdded( UserFactors::CHANGED_ACTION )->once();
		Actions\expectAdded( 'wp_set_password' )->once();
		Actions\expectAdded( 'after_password_reset' )->once();
		Actions\expectAdded( 'profile_update' )->once();

		( new RememberRevoker() )->register();
		$this->assertTrue( true ); // The expectations above are the assertions.
	}

	public function test_a_factor_change_invalidates(): void {
		$this->issue_and_carry();
		( new RememberRevoker() )->on_factor_changed( 5, 'added', 'totp' );

		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_a_password_set_invalidates(): void {
		$this->issue_and_carry();
		( new RememberRevoker() )->on_set_password( 'x', 5 );

		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_a_password_reset_invalidates(): void {
		$this->issue_and_carry();
		( new RememberRevoker() )->on_password_reset( new \WP_User( 5, 'alice' ) );

		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}

	public function test_profile_update_invalidates_only_when_the_hash_changed(): void {
		$old            = new \WP_User( 5, 'alice' );
		$old->user_pass = 'hash-a';
		$new            = new \WP_User( 5, 'alice' );
		$new->user_pass = 'hash-a';
		Functions\when( 'get_userdata' )->alias( static fn () => $new );
		$this->issue_and_carry();

		( new RememberRevoker() )->on_profile_update( 5, $old );
		$this->assertTrue( $this->device()->is_valid( 5 ), 'Same hash: kept.' );

		$new->user_pass = 'hash-b';
		( new RememberRevoker() )->on_profile_update( 5, $old );
		$this->assertFalse( $this->device()->is_valid( 5 ) );
	}
}
