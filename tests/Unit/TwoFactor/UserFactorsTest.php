<?php
/**
 * Tests for the per-user factor store.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\UserFactors
 * @covers \LightweightPlugins\Firewall\TwoFactor\PasskeyRecord
 */
final class UserFactorsTest extends MonkeyTestCase {

	use UserMetaStubTrait;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_user_meta();
		Functions\when( 'wp_salt' )->justReturn( 'salt-one' );
		Functions\when( 'wp_strip_all_tags' )->alias( static fn ( $s ) => strip_tags( (string) $s ) );
	}

	private function record( string $cred, string $label = 'Key' ): PasskeyRecord {
		return new PasskeyRecord( hash( 'sha256', $cred ), $cred, 'PEM', 0, $label, 100, 0 );
	}

	public function test_totp_round_trip_is_sealed(): void {
		$f = new UserFactors( 5 );
		$this->assertFalse( $f->has_totp() );
		$f->save_totp( 'JBSWY3DPEHPK3PXP' );
		$this->assertTrue( $f->has_totp() );
		$this->assertSame( 'JBSWY3DPEHPK3PXP', $f->totp_secret() );
		$this->assertSame( 0, $f->totp_last_step() );
		$this->assertStringNotContainsString( 'JBSWY3DPEHPK3PXP', serialize( $this->user_meta[5]['_lw_firewall_totp'] ) );
	}

	public function test_mark_step_and_delete(): void {
		$f = new UserFactors( 5 );
		$f->save_totp( 'JBSWY3DPEHPK3PXP' );
		$f->mark_totp_step( 99 );
		$this->assertSame( 99, $f->totp_last_step() );
		$this->assertSame( 'JBSWY3DPEHPK3PXP', $f->totp_secret() );
		$f->delete_totp();
		$this->assertFalse( $f->has_totp() );
	}

	public function test_unopenable_secret_means_no_totp(): void {
		$f = new UserFactors( 5 );
		$f->save_totp( 'JBSWY3DPEHPK3PXP' );
		Functions\when( 'wp_salt' )->justReturn( 'rotated' );
		$this->assertNull( $f->totp_secret() );
		$this->assertFalse( $f->has_totp() );
	}

	public function test_recovery_hashes(): void {
		$f = new UserFactors( 5 );
		$this->assertSame( array(), $f->recovery_hashes() );
		$f->set_recovery( array( 'a', 'b' ) );
		$this->assertSame( array( 'a', 'b' ), $f->recovery_hashes() );
	}

	public function test_add_passkey_limits_and_duplicates(): void {
		$f = new UserFactors( 5 );
		for ( $i = 1; $i <= 10; $i++ ) {
			$this->assertTrue( $f->add_passkey( $this->record( "cred$i" ) ) );
		}
		$this->assertFalse( $f->add_passkey( $this->record( 'cred11' ) ) );
		$this->assertFalse( $f->add_passkey( $this->record( 'cred1' ) ) );
		$this->assertCount( 10, $f->passkeys() );
		$this->assertTrue( $f->has_any() );
	}

	public function test_find_user_by_credential_and_remove(): void {
		$f = new UserFactors( 7 );
		$f->add_passkey( $this->record( 'credA' ) );
		$f->add_passkey( $this->record( 'credB' ) );
		$this->assertSame( 7, UserFactors::find_user_by_credential( 'credA' ) );
		$this->assertNull( UserFactors::find_user_by_credential( 'nope' ) );

		$this->assertTrue( $f->remove_passkey( hash( 'sha256', 'credA' ) ) );
		$this->assertFalse( $f->remove_passkey( hash( 'sha256', 'credA' ) ) );
		$this->assertNull( UserFactors::find_user_by_credential( 'credA' ) );
		$this->assertSame( 7, UserFactors::find_user_by_credential( 'credB' ) );
		$this->assertCount( 1, $f->passkeys() );
	}

	public function test_update_passkey_usage(): void {
		$f = new UserFactors( 5 );
		$f->add_passkey( $this->record( 'credA' ) );
		$f->update_passkey_usage( hash( 'sha256', 'credA' ), 42 );
		$p = $f->passkeys()[0];
		$this->assertSame( 42, $p->sign_count );
		$this->assertGreaterThan( 0, $p->last_used_at );
	}

	public function test_user_handle_is_lazy_and_stable(): void {
		$f = new UserFactors( 5 );
		$h = $f->user_handle();
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $h );
		$this->assertSame( $h, $f->user_handle() );
	}

	public function test_reset_all(): void {
		$f = new UserFactors( 5 );
		$f->save_totp( 'JBSWY3DPEHPK3PXP' );
		$f->set_recovery( array( 'a' ) );
		$f->add_passkey( $this->record( 'credA' ) );
		$salt = $f->remember_salt();
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $salt );
		$this->assertSame( $salt, $f->remember_salt() );

		$f->reset_all();
		$this->assertFalse( $f->has_any() );
		$this->assertSame( array(), $f->recovery_hashes() );
		$this->assertNull( UserFactors::find_user_by_credential( 'credA' ) );
		$this->assertNotSame( $salt, $f->remember_salt() );
	}

	public function test_label_is_sanitized_and_capped(): void {
		$r = PasskeyRecord::from_array(
			array(
				'id'            => 'x',
				'credential_id' => 'c',
				'public_key'    => 'p',
				'sign_count'    => 1,
				'label'         => '  <b>' . str_repeat( 'é', 80 ) . '</b> ',
				'created_at'    => 1,
				'last_used_at'  => 0,
			)
		);
		$this->assertNotNull( $r );
		$this->assertSame( str_repeat( 'é', 60 ), $r->label );
	}

	public function test_from_array_missing_field_is_null(): void {
		$this->assertNull( PasskeyRecord::from_array( array( 'id' => 'x' ) ) );
		$r = $this->record( 'c' );
		$this->assertEquals( $r, PasskeyRecord::from_array( $r->to_array() ) );
	}
}
