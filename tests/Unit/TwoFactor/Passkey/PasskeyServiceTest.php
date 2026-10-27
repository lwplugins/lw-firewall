<?php
/**
 * Tests for the passkey service against a library double.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey;

use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\UserMetaStubTrait;
use LightweightPlugins\Firewall\TwoFactor\Passkey\ChallengeStore;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__, 2 ) . '/Support/WpError.php';
require_once dirname( __DIR__, 2 ) . '/Support/WpUser.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService
 */
final class PasskeyServiceTest extends MonkeyTestCase {

	use PasskeyStubTrait;
	use UserMetaStubTrait;

	private FakeWebAuthn $lib;

	private PasskeyService $service;

	private \WP_User $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_passkey_wp();
		$this->stub_user_meta();
		$this->lib     = new FakeWebAuthn();
		$this->service = new PasskeyService( $this->lib );
		$this->alice   = new \WP_User( 5, 'alice', 'Alice A' );
	}

	private static function b64( string $bin ): string {
		return SoftAuthenticator::b64url( $bin );
	}

	private function client_data( string $origin = 'https://example.com' ): string {
		return self::b64( (string) json_encode( array( 'type' => 'x', 'origin' => $origin ) ) );
	}

	/**
	 * Store a passkey for a user; returns its base64url credential id.
	 */
	private function give_key( int $user_id, string $raw_cred, int $count = 0 ): string {
		$cred = self::b64( $raw_cred );
		( new UserFactors( $user_id ) )->add_passkey( new PasskeyRecord( hash( 'sha256', $cred ), $cred, 'PEM-' . $user_id, $count, 'Key', 100, 0 ) );
		return $cred;
	}

	/**
	 * Assertion payload with a given counter.
	 *
	 * @return array<string, string>
	 */
	private function assertion( string $raw_cred, int $count, ?string $handle_bin, string $origin = 'https://example.com' ): array {
		$out = array(
			'id'                => self::b64( $raw_cred ),
			'clientDataJSON'    => $this->client_data( $origin ),
			'authenticatorData' => self::b64( hash( 'sha256', 'example.com', true ) . chr( 5 ) . pack( 'N', $count ) ),
			'signature'         => self::b64( 'sig' ),
		);
		if ( null !== $handle_bin ) {
			$out['userHandle'] = self::b64( $handle_bin );
		}
		return $out;
	}

	private function handle_bin( int $user_id ): string {
		return (string) hex2bin( ( new UserFactors( $user_id ) )->user_handle() );
	}

	private function assert_error( string $code, $result ): void {
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( $code, $result->get_error_code() );
		$this->assertStringNotContainsString( 'SECRET', $result->message );
	}

	// ---- registration -------------------------------------------------------

	public function test_registration_options_require_resident_key_and_uv_and_exclude_existing(): void {
		$this->give_key( 5, 'old-cred' );
		$out = $this->service->registration_options( $this->alice );

		$this->assertIsArray( $out );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $out['key'] );
		$this->assertSame( 'example.com', $out['options']['publicKey']['rp']['id'] );

		$args = $this->lib->calls['getCreateArgs'];
		$this->assertSame( $this->handle_bin( 5 ), $args[0] );
		$this->assertSame( array( 'alice', 'Alice A', 120, true, true, null, array( 'old-cred' ) ), array_slice( $args, 1 ) );

		$this->assertSame(
			array(
				'challenge' => $this->lib->challenge,
				'user_id'   => 5,
			),
			ChallengeStore::take( $out['key'], 'register' )
		);
	}

	public function test_finish_registration_stores_record_with_uv_required(): void {
		$key    = $this->service->registration_options( $this->alice )['key'];
		$record = $this->service->finish_registration( $this->alice, $key, $this->client_data(), self::b64( 'att' ), ' <b>Laptop</b> ' );

		$this->assertInstanceOf( PasskeyRecord::class, $record );
		$this->assertSame( self::b64( 'raw-credential-id' ), $record->credential_id );
		$this->assertSame( hash( 'sha256', $record->credential_id ), $record->id );
		$this->assertSame( 'Laptop', $record->label );
		$this->assertSame( 0, $record->sign_count );
		$this->assertCount( 1, ( new UserFactors( 5 ) )->passkeys() );
		$this->assertSame( 5, UserFactors::find_user_by_credential( $record->credential_id ) );

		$args = $this->lib->calls['processCreate'];
		$this->assertSame( 'att', $args[1] );
		$this->assertSame( $this->lib->challenge, $args[2] );
		$this->assertSame( array( true, true, true, true ), array_slice( $args, 3 ) );
	}

	public function test_finish_registration_default_label(): void {
		$key    = $this->service->registration_options( $this->alice )['key'];
		$record = $this->service->finish_registration( $this->alice, $key, $this->client_data(), self::b64( 'att' ), '<i></i>' );
		$this->assertSame( 'Passkey', $record->label );
	}

	public function test_finish_registration_with_another_users_challenge(): void {
		$key = $this->service->registration_options( new \WP_User( 9, 'bob', 'Bob' ) )['key'];
		$this->assert_error( 'lwfw_passkey_challenge', $this->service->finish_registration( $this->alice, $key, $this->client_data(), self::b64( 'att' ), 'x' ) );
		$this->assertArrayNotHasKey( 'processCreate', $this->lib->calls );
	}

	public function test_finish_registration_replay_and_assert_key(): void {
		$key = $this->service->registration_options( $this->alice )['key'];
		$this->service->finish_registration( $this->alice, $key, $this->client_data(), self::b64( 'att' ), 'x' );
		$this->assert_error( 'lwfw_passkey_challenge', $this->service->finish_registration( $this->alice, $key, $this->client_data(), self::b64( 'att' ), 'x' ) );

		$assert_key = $this->service->assertion_options( $this->alice )['key'];
		$this->assert_error( 'lwfw_passkey_challenge', $this->service->finish_registration( $this->alice, $assert_key, $this->client_data(), self::b64( 'att' ), 'x' ) );
	}

	public function test_library_failure_is_wrapped_and_challenge_is_spent(): void {
		$this->lib->fail = true;
		$key             = $this->service->registration_options( $this->alice )['key'];
		$this->assert_error( 'lwfw_passkey_invalid', $this->service->finish_registration( $this->alice, $key, $this->client_data(), self::b64( 'att' ), 'x' ) );

		$this->lib->fail = false;
		$this->assert_error( 'lwfw_passkey_challenge', $this->service->finish_registration( $this->alice, $key, $this->client_data(), self::b64( 'att' ), 'x' ) );
		$this->assertSame( array(), ( new UserFactors( 5 ) )->passkeys() );
	}

	public function test_registration_rejects_bad_origin_and_bad_encoding(): void {
		$key = $this->service->registration_options( $this->alice )['key'];
		$this->assert_error( 'lwfw_passkey_invalid', $this->service->finish_registration( $this->alice, $key, $this->client_data( 'https://evil.net' ), self::b64( 'att' ), 'x' ) );
		$this->assertArrayNotHasKey( 'processCreate', $this->lib->calls );

		$key = $this->service->registration_options( $this->alice )['key'];
		$this->assert_error( 'lwfw_passkey_invalid', $this->service->finish_registration( $this->alice, $key, $this->client_data(), 'a+b/', 'x' ) );
	}

	public function test_registration_limit_and_foreign_duplicate(): void {
		for ( $i = 0; $i < 10; $i++ ) {
			$this->give_key( 5, "cred$i" );
		}
		$key = $this->service->registration_options( $this->alice )['key'];
		$this->assert_error( 'lwfw_passkey_limit', $this->service->finish_registration( $this->alice, $key, $this->client_data(), self::b64( 'att' ), 'x' ) );

		$this->give_key( 9, 'raw-credential-id' );
		$carol = new \WP_User( 11, 'carol', 'Carol' );
		$key   = $this->service->registration_options( $carol )['key'];
		$this->assert_error( 'lwfw_passkey_limit', $this->service->finish_registration( $carol, $key, $this->client_data(), self::b64( 'att' ), 'x' ) );
		$this->assertSame( array(), ( new UserFactors( 11 ) )->passkeys() );
	}

	// ---- assertion options ----------------------------------------------------

	public function test_assertion_options_discoverable_and_for_user(): void {
		$out = $this->service->assertion_options( null );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $out['key'] );
		$this->assertSame( array(), $this->lib->calls['getGetArgs'][0] );
		$this->assertTrue( $this->lib->calls['getGetArgs'][7] );
		$this->assertSame( 0, ChallengeStore::take( $out['key'], 'assert' )['user_id'] );

		$this->give_key( 5, 'k1' );
		$out = $this->service->assertion_options( $this->alice );
		$this->assertSame( array( 'k1' ), $this->lib->calls['getGetArgs'][0] );
		$this->assertSame( 120, $this->lib->calls['getGetArgs'][1] );
		$this->assertSame( 5, ChallengeStore::take( $out['key'], 'assert' )['user_id'] );
	}

	// ---- verification -------------------------------------------------------

	public function test_unknown_credential(): void {
		$key = $this->service->assertion_options( null )['key'];
		$this->assert_error( 'lwfw_passkey_unknown', $this->service->verify_assertion( $key, $this->assertion( 'nobody', 1, 'h' ) ) );
		$this->assertArrayNotHasKey( 'processGet', $this->lib->calls );
	}

	public function test_failed_attempt_spends_the_challenge(): void {
		$this->give_key( 5, 'k1' );
		$key = $this->service->assertion_options( null )['key'];
		$this->assert_error( 'lwfw_passkey_unknown', $this->service->verify_assertion( $key, $this->assertion( 'nobody', 1, 'h' ) ) );
		$this->assert_error( 'lwfw_passkey_challenge', $this->service->verify_assertion( $key, $this->assertion( 'k1', 1, $this->handle_bin( 5 ) ) ) );
	}

	public function test_discoverable_success_returns_user_and_records_usage(): void {
		$cred = $this->give_key( 5, 'k1' );
		$key  = $this->service->assertion_options( null )['key'];

		$this->assertSame( 5, $this->service->verify_assertion( $key, $this->assertion( 'k1', 3, $this->handle_bin( 5 ) ) ) );

		$args = $this->lib->calls['processGet'];
		$this->assertSame( 'PEM-5', $args[3] );
		$this->assertSame( $this->lib->challenge, $args[4] );
		$this->assertSame( array( null, true, true ), array_slice( $args, 5 ) );

		$record = ( new UserFactors( 5 ) )->passkeys()[0];
		$this->assertSame( $cred, $record->credential_id );
		$this->assertSame( 3, $record->sign_count );
		$this->assertGreaterThan( 0, $record->last_used_at );
	}

	public function test_discoverable_requires_matching_user_handle(): void {
		$this->give_key( 5, 'k1' );
		$this->give_key( 9, 'k9' );

		$key = $this->service->assertion_options( null )['key'];
		$this->assert_error( 'lwfw_passkey_handle', $this->service->verify_assertion( $key, $this->assertion( 'k1', 1, $this->handle_bin( 9 ) ) ) );

		$key = $this->service->assertion_options( null )['key'];
		$this->assert_error( 'lwfw_passkey_handle', $this->service->verify_assertion( $key, $this->assertion( 'k1', 1, null ) ) );

		$key = $this->service->assertion_options( null )['key'];
		$this->assert_error( 'lwfw_passkey_handle', $this->service->verify_assertion( $key, $this->assertion( 'k1', 1, '' ) ) );
		$this->assertArrayNotHasKey( 'processGet', $this->lib->calls );
	}

	public function test_second_factor_binds_to_challenge_user(): void {
		$this->give_key( 5, 'k1' );
		$this->give_key( 9, 'k9' );

		$key = $this->service->assertion_options( $this->alice )['key'];
		$this->assert_error( 'lwfw_passkey_unknown', $this->service->verify_assertion( $key, $this->assertion( 'k9', 1, $this->handle_bin( 9 ) ) ) );

		$key = $this->service->assertion_options( $this->alice )['key'];
		$this->assertSame( 5, $this->service->verify_assertion( $key, $this->assertion( 'k1', 1, null ) ) );

		$key = $this->service->assertion_options( $this->alice )['key'];
		$this->assert_error( 'lwfw_passkey_handle', $this->service->verify_assertion( $key, $this->assertion( 'k1', 2, $this->handle_bin( 9 ) ) ) );
	}

	public function test_sign_count_regression_is_clone(): void {
		$this->give_key( 5, 'k1', 5 );

		foreach ( array( 5, 4, 0 ) as $count ) {
			$key = $this->service->assertion_options( null )['key'];
			$this->assert_error( 'lwfw_passkey_clone', $this->service->verify_assertion( $key, $this->assertion( 'k1', $count, $this->handle_bin( 5 ) ) ) );
		}
		$this->assertSame( 5, ( new UserFactors( 5 ) )->passkeys()[0]->sign_count );

		$key = $this->service->assertion_options( null )['key'];
		$this->assertSame( 5, $this->service->verify_assertion( $key, $this->assertion( 'k1', 6, $this->handle_bin( 5 ) ) ) );
	}

	public function test_zero_counter_authenticators_stay_allowed(): void {
		$this->give_key( 5, 'k1', 0 );
		for ( $i = 0; $i < 2; $i++ ) {
			$key = $this->service->assertion_options( null )['key'];
			$this->assertSame( 5, $this->service->verify_assertion( $key, $this->assertion( 'k1', 0, $this->handle_bin( 5 ) ) ) );
		}
	}

	public function test_library_rejection_is_wrapped(): void {
		$this->give_key( 5, 'k1' );
		$this->lib->fail = true;
		$key             = $this->service->assertion_options( null )['key'];
		$this->assert_error( 'lwfw_passkey_invalid', $this->service->verify_assertion( $key, $this->assertion( 'k1', 1, $this->handle_bin( 5 ) ) ) );
		$this->assertSame( 0, ( new UserFactors( 5 ) )->passkeys()[0]->last_used_at );
	}

	public function test_bad_input_and_origin(): void {
		$this->give_key( 5, 'k1' );

		$key = $this->service->assertion_options( null )['key'];
		$this->assert_error( 'lwfw_passkey_invalid', $this->service->verify_assertion( $key, array( 'id' => 'x' ) ) );

		$key        = $this->service->assertion_options( null )['key'];
		$bad        = $this->assertion( 'k1', 1, $this->handle_bin( 5 ) );
		$bad['signature'] = 'a+b=';
		$this->assert_error( 'lwfw_passkey_invalid', $this->service->verify_assertion( $key, $bad ) );

		$key = $this->service->assertion_options( null )['key'];
		$this->assert_error( 'lwfw_passkey_invalid', $this->service->verify_assertion( $key, $this->assertion( 'k1', 1, $this->handle_bin( 5 ), 'https://evilexample.com' ) ) );

		$key                      = $this->service->assertion_options( null )['key'];
		$short                    = $this->assertion( 'k1', 1, $this->handle_bin( 5 ) );
		$short['authenticatorData'] = self::b64( 'short' );
		$this->assert_error( 'lwfw_passkey_invalid', $this->service->verify_assertion( $key, $short ) );
		$this->assertArrayNotHasKey( 'processGet', $this->lib->calls );
	}

	public function test_registration_key_cannot_be_used_for_assertion(): void {
		$this->give_key( 5, 'k1' );
		$key = $this->service->registration_options( $this->alice )['key'];
		$this->assert_error( 'lwfw_passkey_challenge', $this->service->verify_assertion( $key, $this->assertion( 'k1', 1, $this->handle_bin( 5 ) ) ) );
	}
}
