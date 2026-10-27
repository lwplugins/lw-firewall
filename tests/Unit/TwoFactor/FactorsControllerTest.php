<?php
/**
 * Tests for the two-factor self-service REST routes (profile page).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\SoftAuthenticator;
use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\RecoveryCodes;
use LightweightPlugins\Firewall\TwoFactor\Rest\FactorsController;
use LightweightPlugins\Firewall\TwoFactor\Rest\PasskeysController;
use LightweightPlugins\Firewall\TwoFactor\Rest\PendingTotpSecret;
use LightweightPlugins\Firewall\TwoFactor\Rest\ReAuth;
use LightweightPlugins\Firewall\TwoFactor\Totp;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpRestRequest.php';

/**
 * Alice (5, TOTP, password "alice-pw"), bob (6, nothing, "bob-pw"), carol (7, admin, "carol-pw").
 *
 * @covers \LightweightPlugins\Firewall\TwoFactor\Rest\FactorsController
 * @covers \LightweightPlugins\Firewall\TwoFactor\Rest\PasskeysController
 * @covers \LightweightPlugins\Firewall\TwoFactor\Rest\ReAuth
 * @covers \LightweightPlugins\Firewall\TwoFactor\Rest\PendingTotpSecret
 * @covers \LightweightPlugins\Firewall\TwoFactor\Rest\FactorStatus
 * @covers \LightweightPlugins\Firewall\TwoFactor\RecoveryIssuer
 */
final class FactorsControllerTest extends MonkeyTestCase {

	use LoginFlowTrait {
		setUp as flow_setup;
		tearDown as flow_teardown;
	}

	private const SECRET = 'JBSWY3DPEHPK3PXP';

	private int $current = 5;

	/**
	 * User IDs the current user may edit (besides themselves).
	 *
	 * @var int[]
	 */
	private array $editable = array();

	protected function setUp(): void {
		$this->flow_setup();
		foreach ( array( 5 => 'alice-pw', 6 => 'bob-pw', 7 => 'carol-pw' ) as $id => $pw ) {
			$this->users[ $id ]->user_pass = password_hash( $pw, PASSWORD_BCRYPT, array( 'cost' => 4 ) );
		}
		Functions\when( 'wp_hash_password' )->alias( static fn ( $p ) => password_hash( (string) $p, PASSWORD_BCRYPT, array( 'cost' => 4 ) ) );
		Functions\when( 'is_user_logged_in' )->alias( fn () => $this->current > 0 );
		Functions\when( 'get_current_user_id' )->alias( fn () => $this->current );
		Functions\when( 'wp_get_current_user' )->alias( fn () => $this->users[ $this->current ] ?? new \WP_User( 0 ) );
		Functions\when( 'current_user_can' )->alias(
			fn ( $cap, $id = 0 ) => 'edit_user' === $cap && ( (int) $id === $this->current || in_array( (int) $id, $this->editable, true ) )
		);
		Functions\when( 'rest_authorization_required_code' )->justReturn( 403 );
		Functions\when( 'is_multisite' )->justReturn( false );
		Functions\when( 'absint' )->alias( static fn ( $v ) => abs( (int) $v ) );
	}

	protected function tearDown(): void {
		$this->flow_teardown();
	}

	private function factors(): FactorsController {
		return new FactorsController( $this->throttle, fn (): int => $this->now );
	}

	private function passkeys(): PasskeysController {
		return new PasskeysController( new PasskeyService( $this->lib ), $this->throttle, fn (): int => $this->now );
	}

	/**
	 * @param array<string, mixed> $params Parameters.
	 */
	private function req( array $params = array() ): \WP_REST_Request {
		return new \WP_REST_Request( $params );
	}

	private function assert_error( string $code, int $status, $result ): void {
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( $code, $result->get_error_code() );
		$this->assertSame( $status, $result->get_error_data()['status'] ?? null );
	}

	private function bob_code( string $secret, int $offset = 0 ): string {
		return Totp::code_at( $secret, intdiv( $this->now, 30 ) + $offset );
	}

	/**
	 * Begin + confirm TOTP for the current user; returns the confirm result.
	 *
	 * @param array<string, mixed> $reauth Re-auth parameters for begin.
	 * @return array<string, mixed>|\WP_Error
	 */
	private function enroll_totp( array $reauth = array() ) {
		$begin = $this->factors()->totp_begin( $this->req( $reauth ) );
		$this->assertIsArray( $begin );
		return $this->factors()->totp_confirm( $this->req( array( 'code' => $this->bob_code( $begin['secret'] ) ) ) );
	}

	/**
	 * Register a passkey for the current user (raw credential id varies).
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private function add_passkey( string $raw_id = 'raw-credential-id', array $reauth = array( 'current_password' => 'bob-pw' ) ) {
		$this->lib->create_result = (object) array(
			'credentialId'        => $raw_id,
			'credentialPublicKey' => "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
			'signatureCounter'    => 0,
		);
		$begin = $this->passkeys()->begin( $this->req( $reauth ) );
		$this->assertIsArray( $begin );
		$this->assertSame( array( 'key', 'options' ), array_keys( $begin ) );

		return $this->passkeys()->finish(
			$this->req(
				array(
					'key'        => $begin['key'],
					'label'      => 'Laptop',
					'credential' => array(
						'clientDataJSON'    => SoftAuthenticator::b64url( (string) json_encode( array( 'type' => 'webauthn.create', 'origin' => 'https://example.com' ) ) ),
						'attestationObject' => SoftAuthenticator::b64url( 'att' ),
					),
				)
			)
		);
	}

	// ----- Permissions -----------------------------------------------------

	public function test_logged_out_requests_are_refused(): void {
		$this->current = 0;
		$this->assert_error( 'rest_forbidden', 403, FactorsController::logged_in() );
	}

	public function test_a_non_admin_cannot_read_another_users_factors(): void {
		$this->assert_error( 'rest_forbidden', 403, FactorsController::can_edit( $this->req( array( 'user_id' => 7 ) ) ) );
		$this->assertTrue( FactorsController::can_edit( $this->req( array( 'user_id' => 5 ) ) ) );
	}

	public function test_an_admin_reads_another_users_status(): void {
		$this->current  = 7;
		$this->editable = array( 5 );
		$this->assertTrue( FactorsController::can_edit( $this->req( array( 'user_id' => 5 ) ) ) );

		$status = $this->factors()->user_status( $this->req( array( 'user_id' => 5 ) ) );
		$this->assertTrue( $status['totp'] );
	}

	public function test_nobody_can_reset_themselves_on_the_reset_route(): void {
		$this->assert_error( 'rest_forbidden', 403, FactorsController::can_reset( $this->req( array( 'user_id' => 5 ) ) ) );

		$this->current  = 7;
		$this->editable = array( 5 );
		$this->assert_error( 'rest_forbidden', 403, FactorsController::can_reset( $this->req( array( 'user_id' => 7 ) ) ) );
		$this->assertTrue( FactorsController::can_reset( $this->req( array( 'user_id' => 5 ) ) ) );
	}

	public function test_a_non_admin_cannot_reset_another_user(): void {
		$this->current = 6;
		$this->assert_error( 'rest_forbidden', 403, FactorsController::can_reset( $this->req( array( 'user_id' => 5 ) ) ) );
	}

	// ----- /me -------------------------------------------------------------

	public function test_me_shape_and_the_secret_is_never_in_it(): void {
		( new UserFactors( 5 ) )->add_passkey( new PasskeyRecord( str_repeat( 'a', 64 ), 'cred-a', 'PEM-PUBLIC', 3, 'Phone', 100, 200 ) );
		( new UserFactors( 5 ) )->set_recovery( array( 'h1', 'h2' ) );

		$me = $this->factors()->me();

		$this->assertSame( array( 'totp', 'recovery_left', 'passkeys', 'required', 'grace_ends_at' ), array_keys( $me ) );
		$this->assertTrue( $me['totp'] );
		$this->assertSame( 2, $me['recovery_left'] );
		$this->assertSame(
			array(
				array(
					'id'           => str_repeat( 'a', 64 ),
					'label'        => 'Phone',
					'created_at'   => 100,
					'last_used_at' => 200,
				),
			),
			$me['passkeys']
		);
		$this->assertFalse( $me['required'] );
		$this->assertSame( 0, $me['grace_ends_at'] );

		$json = (string) json_encode( $me );
		$this->assertStringNotContainsString( self::SECRET, $json );
		$this->assertStringNotContainsString( 'cred-a', $json );
		$this->assertStringNotContainsString( 'PEM-PUBLIC', $json );
		$this->assertStringNotContainsString( 'h1', $json );
	}

	public function test_me_never_contains_the_pending_secret(): void {
		$this->current = 6;
		$begin         = $this->factors()->totp_begin( $this->req() );

		$me = $this->factors()->me();
		$this->assertFalse( $me['totp'] );
		$this->assertStringNotContainsString( $begin['secret'], (string) json_encode( $me ) );
	}

	public function test_me_reports_the_requirement_and_grace(): void {
		\LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore::install(
			array(
				'lw_firewall' => array(
					'log_enabled'          => false,
					'twofa_enabled'        => true,
					'twofa_required_roles' => array( 'editor' ),
					'twofa_grace_days'     => 2,
				),
			)
		);
		if ( ! defined( 'DAY_IN_SECONDS' ) ) {
			define( 'DAY_IN_SECONDS', 86400 );
		}
		$this->users[6]->roles = array( 'editor' );
		$this->current         = 6;

		$me = $this->factors()->me();
		$this->assertTrue( $me['required'] );
		$this->assertSame( ( new UserFactors( 6 ) )->grace_since() + 2 * DAY_IN_SECONDS, $me['grace_ends_at'] );
	}

	// ----- TOTP ------------------------------------------------------------

	public function test_totp_begin_returns_secret_and_uri_and_keeps_it_sealed(): void {
		$this->current = 6;
		$begin         = $this->factors()->totp_begin( $this->req() );

		$this->assertSame( array( 'secret', 'uri' ), array_keys( $begin ) );
		$this->assertMatchesRegularExpression( '/^[A-Z2-7]{32}$/', $begin['secret'] );
		$this->assertStringStartsWith( 'otpauth://totp/', $begin['uri'] );
		$this->assertSame( $begin['secret'], PendingTotpSecret::get( 6 ) );
		$stored = (string) json_encode( $this->transients );
		$this->assertStringNotContainsString( $begin['secret'], $stored, 'Sealed at rest.' );
		$this->assertSame( PendingTotpSecret::TTL, current( $this->transients )[1] );
		$this->assertFalse( ( new UserFactors( 6 ) )->has_totp(), 'Nothing is stored before confirm.' );
	}

	public function test_confirm_with_a_wrong_code_is_400_and_saves_nothing(): void {
		$this->current = 6;
		$this->factors()->totp_begin( $this->req() );

		$this->assert_error( FactorsController::CODE_INVALID, 400, $this->factors()->totp_confirm( $this->req( array( 'code' => '000000' ) ) ) );
		$this->assertFalse( ( new UserFactors( 6 ) )->has_totp() );
		$this->assertSame( array(), ( new UserFactors( 6 ) )->recovery_hashes() );
	}

	public function test_confirm_without_begin_is_refused(): void {
		$this->current = 6;
		$this->assert_error( FactorsController::CODE_EXPIRED, 400, $this->factors()->totp_confirm( $this->req( array( 'code' => '123456' ) ) ) );
	}

	public function test_confirm_stores_the_factor_and_returns_ten_recovery_codes_once(): void {
		$this->current = 6;
		$out           = $this->enroll_totp();

		$this->assertCount( 10, $out['recovery_codes'] );
		$factors = new UserFactors( 6 );
		$this->assertTrue( $factors->has_totp() );
		$this->assertGreaterThan( 0, $factors->totp_last_step(), 'The confirming code cannot be replayed.' );
		$this->assertCount( 10, $factors->recovery_hashes() );
		$this->assertNotNull( RecoveryCodes::consume( $out['recovery_codes'][0], $factors->recovery_hashes() ) );
		$this->assertNull( PendingTotpSecret::get( 6 ), 'The pending secret is gone.' );
		$this->assertSame( 10, $this->factors()->me()['recovery_left'] );
	}

	public function test_confirm_keeps_existing_recovery_codes(): void {
		$this->current = 6;
		$this->add_passkey();
		$hashes = ( new UserFactors( 6 ) )->recovery_hashes();

		$out = $this->enroll_totp( array( 'current_password' => 'bob-pw' ) );

		$this->assertSame( array(), $out['recovery_codes'] );
		$this->assertSame( $hashes, ( new UserFactors( 6 ) )->recovery_hashes() );
	}

	public function test_begin_is_refused_while_totp_is_on(): void {
		$this->assert_error( FactorsController::CODE_EXISTS, 409, $this->factors()->totp_begin( $this->req( array( 'current_password' => 'alice-pw' ) ) ) );
	}

	public function test_begin_needs_reauth_once_the_account_has_a_factor(): void {
		$this->current = 6;
		$this->add_passkey();

		$this->assert_error( ReAuth::REQUIRED_CODE, 403, $this->factors()->totp_begin( $this->req() ) );
		$this->assertIsArray( $this->factors()->totp_begin( $this->req( array( 'current_password' => 'bob-pw' ) ) ) );
	}

	public function test_delete_totp_without_password_or_code_is_403(): void {
		$this->assert_error( ReAuth::REQUIRED_CODE, 403, $this->factors()->totp_delete( $this->req() ) );
		$this->assertTrue( ( new UserFactors( 5 ) )->has_totp() );
	}

	public function test_delete_totp_with_a_wrong_password_is_403(): void {
		$this->assert_error( ReAuth::FAILED_CODE, 403, $this->factors()->totp_delete( $this->req( array( 'current_password' => 'nope' ) ) ) );
		$this->assertTrue( ( new UserFactors( 5 ) )->has_totp() );
	}

	public function test_delete_totp_with_the_password(): void {
		( new UserFactors( 5 ) )->set_recovery( array( 'h1' ) );

		$out = $this->factors()->totp_delete( $this->req( array( 'current_password' => 'alice-pw' ) ) );

		$this->assertFalse( $out['totp'] );
		$this->assertFalse( ( new UserFactors( 5 ) )->has_totp() );
		$this->assertSame( array(), ( new UserFactors( 5 ) )->recovery_hashes(), 'No factor left: the codes go too.' );
	}

	public function test_delete_totp_with_a_fresh_code_and_no_replay(): void {
		( new UserFactors( 5 ) )->add_passkey( new PasskeyRecord( str_repeat( 'b', 64 ), 'cred-b', 'PEM', 0, 'Key', 1, 0 ) );
		( new UserFactors( 5 ) )->set_recovery( array( 'h1' ) );
		$code = $this->code();

		$this->assertIsArray( $this->factors()->totp_delete( $this->req( array( 'code' => $code ) ) ) );
		$this->assertFalse( ( new UserFactors( 5 ) )->has_totp() );
		$this->assertSame( array( 'h1' ), ( new UserFactors( 5 ) )->recovery_hashes(), 'A passkey is left: the codes stay.' );
	}

	public function test_a_replayed_code_is_not_reauth(): void {
		$code = $this->code();
		( new UserFactors( 5 ) )->mark_totp_step( intdiv( $this->now, 30 ) );

		$this->assert_error( ReAuth::FAILED_CODE, 403, $this->factors()->totp_delete( $this->req( array( 'code' => $code ) ) ) );
		$this->assertTrue( ( new UserFactors( 5 ) )->has_totp() );
	}

	public function test_reauth_failures_are_throttled(): void {
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->factors()->totp_delete( $this->req( array( 'current_password' => 'wrong-' . $i ) ) );
		}

		$this->assertTrue( $this->throttle->is_blocked( 5 ) );
		$this->assert_error( ReAuth::BLOCKED_CODE, 429, $this->factors()->totp_delete( $this->req( array( 'current_password' => 'alice-pw' ) ) ) );
		$this->assertTrue( ( new UserFactors( 5 ) )->has_totp(), 'Even the right password waits out the block.' );
	}

	public function test_a_successful_reauth_restores_the_budget(): void {
		$this->factors()->recovery_regenerate( $this->req( array( 'current_password' => 'wrong' ) ) );
		$this->factors()->recovery_regenerate( $this->req( array( 'current_password' => 'alice-pw' ) ) );

		$this->assertSame( 0, $this->storage->count( 5, FailureThrottle::META_KEY, FailureThrottle::WINDOW ) );
	}

	// ----- Recovery codes and devices --------------------------------------

	public function test_regenerate_requires_reauth(): void {
		( new UserFactors( 5 ) )->set_recovery( array( 'old' ) );

		$this->assert_error( ReAuth::REQUIRED_CODE, 403, $this->factors()->recovery_regenerate( $this->req() ) );
		$this->assertSame( array( 'old' ), ( new UserFactors( 5 ) )->recovery_hashes() );

		$out = $this->factors()->recovery_regenerate( $this->req( array( 'code' => $this->code() ) ) );
		$this->assertCount( 10, $out['recovery_codes'] );
		$this->assertCount( 10, ( new UserFactors( 5 ) )->recovery_hashes() );
		$this->assertNotContains( 'old', ( new UserFactors( 5 ) )->recovery_hashes() );
	}

	public function test_regenerate_needs_a_factor(): void {
		$this->current = 6;
		$this->assert_error( FactorsController::CODE_NO_FACTOR, 409, $this->factors()->recovery_regenerate( $this->req( array( 'current_password' => 'bob-pw' ) ) ) );
	}

	public function test_forget_devices_requires_reauth_and_rotates_the_salt(): void {
		$salt = ( new UserFactors( 5 ) )->remember_salt();

		$this->assert_error( ReAuth::REQUIRED_CODE, 403, $this->factors()->devices_forget( $this->req() ) );
		$this->assertSame( $salt, ( new UserFactors( 5 ) )->remember_salt() );

		$this->assertSame( array( 'forgotten' => true ), $this->factors()->devices_forget( $this->req( array( 'current_password' => 'alice-pw' ) ) ) );
		$this->assertNotSame( $salt, ( new UserFactors( 5 ) )->remember_salt() );
	}

	// ----- Admin reset -----------------------------------------------------

	public function test_admin_reset_needs_the_admins_own_password(): void {
		$this->current  = 7;
		$this->editable = array( 5 );

		$this->assert_error( ReAuth::REQUIRED_CODE, 403, $this->factors()->reset( $this->req( array( 'user_id' => 5 ) ) ) );
		$this->assert_error( ReAuth::FAILED_CODE, 403, $this->factors()->reset( $this->req( array( 'user_id' => 5, 'current_password' => 'alice-pw' ) ) ) );
		$this->assertTrue( ( new UserFactors( 5 ) )->has_totp() );

		$out = $this->factors()->reset( $this->req( array( 'user_id' => 5, 'current_password' => 'carol-pw' ) ) );
		$this->assertFalse( $out['totp'] );
		$this->assertFalse( ( new UserFactors( 5 ) )->has_any() );
	}

	public function test_admin_reset_does_not_take_a_totp_code(): void {
		$this->current  = 7;
		$this->editable = array( 5 );
		( new UserFactors( 7 ) )->save_totp( self::SECRET );

		$this->assert_error( ReAuth::REQUIRED_CODE, 403, $this->factors()->reset( $this->req( array( 'user_id' => 5, 'code' => $this->code() ) ) ) );
		$this->assertTrue( ( new UserFactors( 5 ) )->has_totp() );
	}

	// ----- Passkeys --------------------------------------------------------

	public function test_passkey_begin_requires_reauth(): void {
		$this->current = 6;
		$this->assert_error( ReAuth::REQUIRED_CODE, 403, $this->passkeys()->begin( $this->req() ) );
		$this->assertSame( array(), $this->transients, 'No challenge issued.' );
	}

	public function test_the_first_passkey_issues_recovery_codes(): void {
		$this->current = 6;
		$out           = $this->add_passkey();

		$this->assertSame( array( 'passkey', 'recovery_codes' ), array_keys( $out ) );
		$this->assertSame( 'Laptop', $out['passkey']['label'] );
		$this->assertSame( array( 'id', 'label', 'created_at', 'last_used_at' ), array_keys( $out['passkey'] ) );
		$this->assertCount( 10, $out['recovery_codes'] );
		$this->assertCount( 10, ( new UserFactors( 6 ) )->recovery_hashes() );

		$second = $this->add_passkey( 'another-credential' );
		$this->assertSame( array(), $second['recovery_codes'] );
		$this->assertCount( 2, ( new UserFactors( 6 ) )->passkeys() );
	}

	public function test_a_rejected_registration_is_400(): void {
		$this->current  = 6;
		$this->lib->fail = true;

		$this->assert_error( PasskeysController::CODE_REJECTED, 400, $this->add_passkey() );
		$this->assertSame( array(), ( new UserFactors( 6 ) )->recovery_hashes() );
	}

	public function test_passkey_delete_requires_reauth_and_drops_unused_codes(): void {
		$this->current = 6;
		$id            = $this->add_passkey()['passkey']['id'];

		$this->assert_error( ReAuth::REQUIRED_CODE, 403, $this->passkeys()->delete( $this->req( array( 'id' => $id ) ) ) );
		$this->assertCount( 1, ( new UserFactors( 6 ) )->passkeys() );

		$out = $this->passkeys()->delete( $this->req( array( 'id' => $id, 'current_password' => 'bob-pw' ) ) );
		$this->assertSame( array(), $out['passkeys'] );
		$this->assertSame( array(), ( new UserFactors( 6 ) )->recovery_hashes() );
	}

	public function test_deleting_an_unknown_passkey_is_404(): void {
		$this->assert_error( PasskeysController::CODE_UNKNOWN, 404, $this->passkeys()->delete( $this->req( array( 'id' => str_repeat( 'f', 64 ), 'current_password' => 'alice-pw' ) ) ) );
	}

	public function test_routes_are_registered_with_permission_callbacks(): void {
		$routes = array();
		Functions\when( 'register_rest_route' )->alias(
			function ( $ns, $route, $args ) use ( &$routes ) {
				$routes[ $route ] = $args;
				return true;
			}
		);
		$this->factors()->register_routes();
		$this->passkeys()->register_routes();

		$expected = array(
			'/2fa/me',
			'/2fa/totp/begin',
			'/2fa/totp/confirm',
			'/2fa/totp',
			'/2fa/recovery/regenerate',
			'/2fa/devices/forget',
			'/2fa/users/(?P<user_id>\d+)',
			'/2fa/users/(?P<user_id>\d+)/reset',
			'/2fa/passkeys/begin',
			'/2fa/passkeys/finish',
			'/2fa/passkeys/(?P<id>[a-f0-9]{64})',
		);
		$this->assertEqualsCanonicalizing( $expected, array_keys( $routes ) );
		foreach ( $routes as $route => $args ) {
			$this->assertIsCallable( $args['permission_callback'], $route );
			$this->assertNotSame( '__return_true', $args['permission_callback'], $route );
		}
		$this->assertSame( 'DELETE', $routes['/2fa/totp']['methods'] );
		$this->assertSame( 'GET', $routes['/2fa/me']['methods'] );
	}
}
