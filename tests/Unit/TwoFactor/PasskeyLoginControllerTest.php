<?php
/**
 * Tests for the passwordless passkey login (REST options/verify).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\SoftAuthenticator;
use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\LoginInterceptor;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\Rest\PasskeyLoginController;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpRestRequest.php';
require_once dirname( __DIR__ ) . '/Support/ArrayStorage.php';

/**
 * Alice (5) has TOTP and a passkey; carol (7) gets TOTP where a test needs a second user.
 *
 * @covers \LightweightPlugins\Firewall\TwoFactor\Rest\PasskeyLoginController
 * @covers \LightweightPlugins\Firewall\TwoFactor\LoginInterceptor
 */
final class PasskeyLoginControllerTest extends MonkeyTestCase {

	use LoginFlowTrait {
		setUp as flow_setup;
		tearDown as flow_teardown;
	}

	private const SECRET = 'JBSWY3DPEHPK3PXP';

	private ArrayStorage $rate;

	private PasskeyService $service;

	private string $cred = '';

	protected function setUp(): void {
		$this->flow_setup();
		Functions\when( 'is_multisite' )->justReturn( false );
		$this->rate    = new ArrayStorage();
		$this->service = new PasskeyService( $this->lib );
		$this->cred    = SoftAuthenticator::b64url( 'alice-key' );
		( new UserFactors( 5 ) )->add_passkey( new PasskeyRecord( hash( 'sha256', $this->cred ), $this->cred, 'PEM', 0, 'Key', 100, 0 ) );
	}

	protected function tearDown(): void {
		LoginInterceptor::cancel_skip();
		$this->flow_teardown();
	}

	private function controller(): PasskeyLoginController {
		return new PasskeyLoginController( $this->service, $this->rate, $this->throttle );
	}

	/**
	 * A discoverable assertion for alice's passkey.
	 *
	 * @return array<string, string>
	 */
	private function assertion( int $count = 1, string $raw_cred = 'alice-key' ): array {
		return array(
			'id'                => SoftAuthenticator::b64url( $raw_cred ),
			'clientDataJSON'    => SoftAuthenticator::b64url( (string) json_encode( array( 'type' => 'webauthn.get', 'origin' => 'https://example.com' ) ) ),
			'authenticatorData' => SoftAuthenticator::b64url( hash( 'sha256', 'example.com', true ) . chr( 5 ) . pack( 'N', $count ) ),
			'signature'         => SoftAuthenticator::b64url( 'sig' ),
			'userHandle'        => SoftAuthenticator::b64url( (string) hex2bin( ( new UserFactors( 5 ) )->user_handle() ) ),
		);
	}

	/**
	 * @param array<string, mixed> $params Request parameters.
	 * @return array<string, mixed>|\WP_Error
	 */
	private function verify( array $params ) {
		return $this->controller()->verify( new \WP_REST_Request( $params ) );
	}

	private function key(): string {
		$out = $this->controller()->options();
		$this->assertIsArray( $out );
		return $out['key'];
	}

	private function assert_refused( int $status, $result ): void {
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( $status, $result->get_error_data()['status'] ?? null );
		$this->assertStringNotContainsString( 'lwfw_passkey_', $result->message, 'Library/service codes never reach the browser.' );
		$this->assertStringStartsWith( 'lwfw_pkl_', $result->get_error_code() );
		$this->assertSame( array(), $this->cookies, 'No session on a refusal.' );
	}

	// ---- rate limit -----------------------------------------------------------

	public function test_the_21st_request_per_ip_is_rate_limited(): void {
		$controller = $this->controller();
		for ( $i = 1; $i <= 20; $i++ ) {
			$this->assertTrue( $controller->rate_limit(), "Request $i is allowed." );
		}

		$result = $controller->rate_limit();
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 429, $result->get_error_data()['status'] );

		$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
		$this->assertTrue( $controller->rate_limit(), 'Another IP has its own budget.' );
	}

	public function test_options_are_discoverable(): void {
		$out = $this->controller()->options();

		$this->assertIsArray( $out );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $out['key'] );
		$this->assertSame( array(), $this->lib->calls['getGetArgs'][0], 'No allowCredentials: the browser picks the account.' );
	}

	// ---- refusals ----------------------------------------------------------

	public function test_unknown_challenge_key_is_400(): void {
		$this->assert_refused( 400, $this->verify( array( 'key' => str_repeat( 'a', 32 ), 'credential' => $this->assertion() ) ) );
		$this->assert_refused( 400, $this->verify( array( 'key' => 'nope', 'credential' => $this->assertion() ) ) );
		$this->assert_refused( 400, $this->verify( array( 'key' => array( 'x' ), 'credential' => 'junk' ) ) );
	}

	public function test_used_challenge_key_is_400(): void {
		$key = $this->key();
		$this->assertIsArray( $this->verify( array( 'key' => $key, 'credential' => $this->assertion( 1 ) ) ) );
		$this->cookies = array();
		LoginInterceptor::cancel_skip();

		$this->assert_refused( 400, $this->verify( array( 'key' => $key, 'credential' => $this->assertion( 2 ) ) ) );
	}

	public function test_a_second_factor_challenge_cannot_sign_in(): void {
		$out = $this->service->assertion_options( $this->users[5] );
		$this->assertIsArray( $out );

		$this->assert_refused( 400, $this->verify( array( 'key' => $out['key'], 'credential' => $this->assertion() ) ) );
	}

	public function test_library_rejection_is_generic_and_counted_without_the_account_throttle(): void {
		$this->lib->fail = true;
		Actions\expectDone( 'wp_login_failed' )->once()->with( 'alice', \Mockery::type( \WP_Error::class ) );

		$this->assert_refused( 400, $this->verify( array( 'key' => $this->key(), 'credential' => $this->assertion() ) ) );
		$this->assertSame( 0, $this->storage->count( 5, FailureThrottle::META_KEY, FailureThrottle::WINDOW ), 'Junk with a victim credential id must not lock the victim out.' );
	}

	public function test_unknown_credential_reports_an_empty_username(): void {
		Actions\expectDone( 'wp_login_failed' )->once()->with( '', \Mockery::type( \WP_Error::class ) );

		$this->assert_refused( 400, $this->verify( array( 'key' => $this->key(), 'credential' => $this->assertion( 1, 'nobody-key' ) ) ) );
	}

	public function test_throttled_account_is_403(): void {
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->throttle->claim( 5 );
		}
		$this->assertTrue( $this->throttle->is_blocked( 5 ) );

		$this->assert_refused( 403, $this->verify( array( 'key' => $this->key(), 'credential' => $this->assertion() ) ) );
	}

	public function test_spam_account_on_multisite_is_403(): void {
		Functions\when( 'is_multisite' )->justReturn( true );
		Functions\when( 'is_user_spammy' )->justReturn( true );

		$this->assert_refused( 403, $this->verify( array( 'key' => $this->key(), 'credential' => $this->assertion() ) ) );
	}

	// ---- success -----------------------------------------------------------

	public function test_success_sets_the_session_and_wp_login_does_not_hold_it(): void {
		$interceptor = $this->interceptor();
		Actions\expectDone( 'wp_login' )->once()->whenHappen(
			static function ( $login, $user ) use ( $interceptor ): void {
				$interceptor->on_wp_login( $login, $user );
			}
		);

		$result = $this->verify(
			array(
				'key'         => $this->key(),
				'credential'  => $this->assertion(),
				'remember'    => true,
				'redirect_to' => 'https://example.com/wp-admin/edit.php',
			)
		);

		$this->assertSame( array( 'redirect' => 'https://example.com/wp-admin/edit.php' ), $result );
		$this->assertSame( array( array( 5, true ) ), $this->cookies );
		$this->assertSame( 0, $this->cleared, 'The cookie is not cleared.' );
		$this->assertSame( array(), $this->redirects, 'No pending second-factor page.' );
		$this->assertSame( 0, $this->halts );
	}

	public function test_external_redirect_falls_back_to_admin(): void {
		$result = $this->verify(
			array(
				'key'         => $this->key(),
				'credential'  => $this->assertion(),
				'redirect_to' => 'https://evil.example.net/',
			)
		);

		$this->assertSame( array( 'redirect' => 'https://example.com/wp-admin/' ), $result );
		$this->assertSame( array( array( 5, false ) ), $this->cookies );
	}

	public function test_password_logins_after_a_passkey_login_are_still_held(): void {
		$interceptor = $this->interceptor();
		Actions\expectDone( 'wp_login' )->once()->whenHappen(
			static function ( $login, $user ) use ( $interceptor ): void {
				$interceptor->on_wp_login( $login, $user );
			}
		);
		$this->assertIsArray( $this->verify( array( 'key' => $this->key(), 'credential' => $this->assertion() ) ) );

		// Same request, same user, password path: held for the second factor.
		$this->assertNotSame( '', $this->login( 5, $interceptor ) );
	}

	public function test_skip_once_is_single_use_and_bound_to_the_user(): void {
		( new UserFactors( 7 ) )->save_totp( self::SECRET );
		$interceptor = $this->interceptor();

		LoginInterceptor::skip_once( 5 );
		$this->assertNotSame( '', $this->login( 7, $interceptor ), 'Another user is still held.' );

		$before = count( $this->redirects );
		$interceptor->on_wp_login( 'alice', $this->users[5] );
		$this->assertCount( $before, $this->redirects, 'The flagged user passes once.' );

		$this->assertNotSame( '', $this->login( 5, $interceptor ), 'The flag is spent.' );
	}

	public function test_the_skip_is_cancelled_even_when_a_wp_login_listener_throws(): void {
		Actions\expectDone( 'wp_login' )->once()->whenHappen(
			static function (): void {
				throw new \LogicException( 'listener' );
			}
		);

		try {
			$this->verify( array( 'key' => $this->key(), 'credential' => $this->assertion() ) );
			$this->fail( 'Expected the listener exception.' );
		} catch ( \LogicException $e ) {
			$this->assertSame( 'listener', $e->getMessage() );
		}

		$this->assertNotSame( '', $this->login( 5, $this->interceptor() ) );
	}
}
