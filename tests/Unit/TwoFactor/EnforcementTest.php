<?php
/**
 * Tests for role-based two-factor enforcement and the grace-period notice.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\TwoFactor\Enforcement;
use LightweightPlugins\Firewall\TwoFactor\EnrollmentNotice;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpUser.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\Enforcement
 * @covers \LightweightPlugins\Firewall\TwoFactor\EnrollmentNotice
 */
final class EnforcementTest extends MonkeyTestCase {

	use UserMetaStubTrait;

	private const DAY = 86400;

	private int $now = 1700000000;

	private bool $multisite = false;

	/**
	 * Super admin IDs.
	 *
	 * @var int[]
	 */
	private array $supers = array();

	protected function setUp(): void {
		parent::setUp();
		if ( ! defined( 'DAY_IN_SECONDS' ) ) {
			define( 'DAY_IN_SECONDS', self::DAY );
		}
		$this->stub_user_meta();
		Functions\stubEscapeFunctions();
		Functions\stubTranslationFunctions();
		Functions\when( 'wp_salt' )->justReturn( 'salt' );
		Functions\when( 'wp_strip_all_tags' )->alias( static fn ( $s ) => strip_tags( (string) $s ) );
		Functions\when( 'is_multisite' )->alias( fn () => $this->multisite );
		Functions\when( 'is_super_admin' )->alias( fn ( $id = false ) => in_array( (int) $id, $this->supers, true ) );
		Functions\when( 'admin_url' )->alias( static fn ( $path = '' ) => 'https://example.com/wp-admin/' . $path );
		$this->options( array( 'editor' ), 7 );
	}

	/**
	 * @param string[] $roles Required roles.
	 */
	private function options( array $roles, int $grace, bool $enabled = true ): void {
		OptionStore::install(
			array(
				'lw_firewall' => array(
					'twofa_enabled'        => $enabled,
					'twofa_required_roles' => $roles,
					'twofa_grace_days'     => $grace,
				),
			)
		);
	}

	private function enforcement(): Enforcement {
		return new Enforcement( fn (): int => $this->now );
	}

	/**
	 * @param string[] $roles Roles.
	 */
	private function user( int $id, array $roles ): \WP_User {
		return new \WP_User( $id, 'user' . $id, '', $roles );
	}

	public function test_a_role_outside_the_list_is_not_required(): void {
		$user = $this->user( 3, array( 'subscriber' ) );

		$this->assertFalse( $this->enforcement()->is_required( $user ) );
		$this->now += 30 * self::DAY;
		$this->assertFalse( $this->enforcement()->must_enroll_now( $user ) );
		$this->assertArrayNotHasKey( UserFactors::META_SINCE, $this->user_meta[3] ?? array(), 'No grace clock for users who are not required.' );
	}

	public function test_a_listed_role_is_required(): void {
		$this->assertTrue( $this->enforcement()->is_required( $this->user( 3, array( 'subscriber', 'editor' ) ) ) );
	}

	public function test_required_with_a_factor_never_has_to_enroll(): void {
		$user = $this->user( 3, array( 'editor' ) );
		( new UserFactors( 3 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );
		$this->enforcement()->grace_ends_at( $user );
		$this->now += 30 * self::DAY;

		$this->assertFalse( $this->enforcement()->must_enroll_now( $user ) );
	}

	public function test_a_passkey_counts_as_a_factor(): void {
		$user = $this->user( 3, array( 'editor' ) );
		( new UserFactors( 3 ) )->add_passkey( new PasskeyRecord( str_repeat( 'a', 64 ), 'cred', 'PEM', 0, 'Key', 1, 0 ) );
		$this->options( array( 'editor' ), 0 );

		$this->assertFalse( $this->enforcement()->must_enroll_now( $user ) );
	}

	public function test_without_factors_inside_the_grace_period_not_yet(): void {
		$user = $this->user( 3, array( 'editor' ) );

		$this->assertFalse( $this->enforcement()->must_enroll_now( $user ) );
		$this->assertSame( $this->now, (int) $this->user_meta[3][ UserFactors::META_SINCE ][0], 'The grace clock starts on the first evaluation.' );

		$this->now += 6 * self::DAY;
		$this->assertFalse( $this->enforcement()->must_enroll_now( $user ) );
	}

	public function test_eight_days_into_a_seven_day_grace_must_enroll(): void {
		$user  = $this->user( 3, array( 'editor' ) );
		$start = $this->now;
		$this->enforcement()->must_enroll_now( $user );

		$this->now += 8 * self::DAY;

		$this->assertTrue( $this->enforcement()->must_enroll_now( $user ) );
		$this->assertSame( $start + 7 * self::DAY, $this->enforcement()->grace_ends_at( $user ), 'The start is written once, not moved.' );
	}

	public function test_zero_grace_days_means_now(): void {
		$this->options( array( 'editor' ), 0 );

		$this->assertTrue( $this->enforcement()->must_enroll_now( $this->user( 3, array( 'editor' ) ) ) );
	}

	public function test_nothing_is_required_while_the_module_is_off(): void {
		$this->options( array( 'editor', 'administrator' ), 0, false );
		$user = $this->user( 3, array( 'editor' ) );

		$this->assertFalse( $this->enforcement()->is_required( $user ) );
		$this->assertFalse( $this->enforcement()->must_enroll_now( $user ) );
	}

	public function test_the_grace_start_is_written_once(): void {
		$user   = $this->user( 3, array( 'editor' ) );
		$writes = 0;
		Functions\when( 'update_user_meta' )->alias(
			function ( $id, $key, $value ) use ( &$writes ) {
				++$writes;
				$this->user_meta[ (int) $id ][ $key ] = array( $value );
				return true;
			}
		);

		for ( $i = 0; $i < 5; $i++ ) {
			$this->enforcement()->grace_ends_at( $user );
			$this->now += 60;
		}

		$this->assertSame( 1, $writes );
	}

	public function test_a_user_who_becomes_required_later_starts_the_grace_then(): void {
		$user = $this->user( 3, array( 'author' ) );
		$this->enforcement()->must_enroll_now( $user );

		$this->now  += 30 * self::DAY;
		$user->roles = array( 'editor' );

		$this->assertFalse( $this->enforcement()->must_enroll_now( $user ) );
		$this->assertSame( $this->now + 7 * self::DAY, $this->enforcement()->grace_ends_at( $user ) );
	}

	public function test_a_factor_reset_keeps_the_old_grace_start(): void {
		$user = $this->user( 3, array( 'editor' ) );
		( new UserFactors( 3 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );
		$this->enforcement()->must_enroll_now( $user );
		$this->now += 30 * self::DAY;

		( new UserFactors( 3 ) )->reset_all();

		$this->assertTrue( $this->enforcement()->must_enroll_now( $user ), 'A reset does not open a fresh password-only window.' );
	}

	public function test_super_admins_count_as_administrators_on_multisite(): void {
		$this->options( array( 'administrator' ), 0 );
		$this->multisite = true;
		$this->supers    = array( 9 );

		$this->assertTrue( $this->enforcement()->is_required( $this->user( 9, array() ) ) );
		$this->assertFalse( $this->enforcement()->is_required( $this->user( 8, array() ) ) );

		$this->options( array( 'editor' ), 0 );
		$this->assertFalse( $this->enforcement()->is_required( $this->user( 9, array() ) ), 'Only when administrators are required.' );
	}

	public function test_days_left_rounds_up(): void {
		$user = $this->user( 3, array( 'editor' ) );
		$this->enforcement()->grace_ends_at( $user );

		$this->assertSame( 7, $this->enforcement()->days_left( $user ) );
		$this->now += 6 * self::DAY + 1;
		$this->assertSame( 1, $this->enforcement()->days_left( $user ) );
	}

	// ---- notice -------------------------------------------------------------

	private function notice_for( \WP_User $user ): string {
		Functions\when( 'wp_get_current_user' )->justReturn( $user );
		ob_start();
		( new EnrollmentNotice( $this->enforcement() ) )->render();
		return (string) ob_get_clean();
	}

	public function test_the_notice_shows_during_the_grace_period(): void {
		$html = $this->notice_for( $this->user( 3, array( 'editor' ) ) );

		$this->assertStringContainsString( 'dashicons-', $html );
		$this->assertStringContainsString( '7 days', $html );
		$this->assertStringContainsString( 'https://example.com/wp-admin/profile.php#lw-firewall-2fa', $html );
	}

	public function test_no_notice_for_users_who_are_not_required_or_have_factors(): void {
		$this->assertSame( '', $this->notice_for( $this->user( 3, array( 'subscriber' ) ) ) );

		( new UserFactors( 4 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );
		$this->assertSame( '', $this->notice_for( $this->user( 4, array( 'editor' ) ) ) );

		$this->assertSame( '', $this->notice_for( new \WP_User( 0, '' ) ), 'Logged out.' );
	}

	public function test_no_notice_after_the_grace_period(): void {
		$user = $this->user( 3, array( 'editor' ) );
		$this->enforcement()->grace_ends_at( $user );
		$this->now += 8 * self::DAY;

		$this->assertSame( '', $this->notice_for( $user ), 'The login screen takes over.' );
	}

	public function test_the_notice_is_wired_to_admin_notices_only(): void {
		$notice = new EnrollmentNotice( $this->enforcement() );
		$notice->register();

		$this->assertNotFalse( has_action( 'admin_notices', array( $notice, 'render' ) ) );
		$this->assertFalse( has_action( 'network_admin_notices', array( $notice, 'render' ) ) );
	}
}
