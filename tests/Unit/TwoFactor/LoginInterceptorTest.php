<?php
/**
 * Tests for the second-factor login interception and challenge handling.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\FakeWpdb;
use LightweightPlugins\Firewall\TwoFactor\AttemptCounter;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\FakeWebAuthn;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\PasskeyStubTrait;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\SoftAuthenticator;
use LightweightPlugins\Firewall\TwoFactor\FailureLog;
use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\ChallengePage;
use LightweightPlugins\Firewall\TwoFactor\LoginInterceptor;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\PendingLogin;
use LightweightPlugins\Firewall\TwoFactor\RememberDevice;
use LightweightPlugins\Firewall\TwoFactor\RequestContext;
use LightweightPlugins\Firewall\TwoFactor\SecondFactorVerifier;
use LightweightPlugins\Firewall\TwoFactor\SignonTracker;
use LightweightPlugins\Firewall\TwoFactor\Totp;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpError.php';
require_once dirname( __DIR__ ) . '/Support/WpUser.php';
require_once dirname( __DIR__ ) . '/Support/WpSessionTokens.php';

require_once dirname( __DIR__ ) . '/Support/FakeWpdb.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\LoginInterceptor
 * @covers \LightweightPlugins\Firewall\TwoFactor\LoginRequest
 * @covers \LightweightPlugins\Firewall\TwoFactor\SecondFactorVerifier
 * @covers \LightweightPlugins\Firewall\TwoFactor\ChallengePage
 * @covers \LightweightPlugins\Firewall\TwoFactor\ChallengeController
 * @covers \LightweightPlugins\Firewall\TwoFactor\FailureLog
 * @covers \LightweightPlugins\Firewall\TwoFactor\FailureThrottle
 * @covers \LightweightPlugins\Firewall\TwoFactor\SignonTracker
 * @covers \LightweightPlugins\Firewall\TwoFactor\PendingLogin
 */
final class LoginInterceptorTest extends MonkeyTestCase {

	use LoginFlowTrait;

	private const SECRET = 'JBSWY3DPEHPK3PXP';

	// ---- password step ------------------------------------------------------

	public function test_a_user_without_factors_is_not_touched(): void {
		$this->interceptor()->on_wp_login( 'bob', $this->users[6] );

		$this->assertSame( 0, $this->cleared );
		$this->assertSame( array(), $this->redirects );
		$this->assertSame( 0, $this->halts );
	}

	public function test_a_two_factor_user_is_logged_out_and_sent_to_the_challenge(): void {
		$token = $this->login( 5, $this->interceptor() );

		$this->assertSame( 1, $this->cleared );
		$this->assertSame( 1, $this->halts );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/D', $token );
		$this->assertStringContainsString( 'action=lw_firewall_2fa', $this->redirects[0] );
		$this->assertStringContainsString( 'token=' . $token, $this->redirects[0] );
	}

	public function test_non_interactive_requests_are_left_alone(): void {
		foreach ( array( 'xmlrpc', 'rest', 'ajax', 'cron', 'cli' ) as $flag ) {
			$this->interceptor( array( $flag => true ) )->on_wp_login( 'alice', $this->users[5] );
		}

		$this->assertSame( 0, $this->cleared );
		$this->assertSame( array(), $this->redirects );
	}

	public function test_the_signon_cookie_is_withheld_and_its_session_destroyed(): void {
		$interceptor = $this->interceptor();

		$this->assertTrue( $interceptor->filter_send_cookies( true, 0, 0, 5, 'auth', 'tok-before' ), 'Outside wp_signon nothing is withheld.' );

		$this->signon->start( 'alice', 'pw' );
		$this->assertFalse( $interceptor->filter_send_cookies( true, 0, 0, 5, 'secure_auth', 'tok-1' ) );
		$this->assertTrue( $interceptor->filter_send_cookies( true, 0, 0, 6, 'auth', 'tok-bob' ), 'A user without factors keeps the cookie.' );
		$this->assertTrue( $interceptor->filter_send_cookies( true, 0, 0, 0, '', '' ), 'Clearing cookies is never blocked.' );

		$this->login( 5, $interceptor );

		$this->assertSame( array( 5 => array( 'tok-before', 'tok-1' ) ), \WP_Session_Tokens::$destroyed, 'Every token issued for the user in this request dies.' );
	}

	public function test_redirect_to_is_kept_and_validated(): void {
		$_REQUEST['redirect_to'] = 'https://example.com/wp-admin/edit.php';
		$_POST['rememberme']     = 'forever';
		$interceptor             = $this->interceptor();
		$token                   = $this->login( 5, $interceptor );

		$record = $this->store()->get( $token );
		$this->assertSame( 'https://example.com/wp-admin/edit.php', $record['redirect_to'] ?? null );
		$this->assertTrue( $record['remember'] ?? null );

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );
		$this->assertSame( 'https://example.com/wp-admin/edit.php', end( $this->redirects ) );
	}

	public function test_woocommerce_redirect_field_and_foreign_targets(): void {
		$_REQUEST['redirect'] = 'https://example.com/my-account/';
		$token                = $this->login( 5, $this->interceptor() );
		$this->assertSame( 'https://example.com/my-account/', $this->store()->get( $token )['redirect_to'] ?? null );

		$_REQUEST = array( 'redirect_to' => 'https://evil.example/' );
		$token    = $this->login( 5, $this->interceptor() );
		$this->assertSame( 'https://example.com/wp-admin/', $this->store()->get( $token )['redirect_to'] ?? null );
	}

	// ---- challenge ----------------------------------------------------------

	public function test_get_renders_the_challenge(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		$html = $this->open( $interceptor, $token );

		$this->assertStringContainsString( 'autocomplete="one-time-code"', $html );
		$this->assertStringContainsString( 'inputmode="numeric"', $html );
		$this->assertStringContainsString( 'value="' . $token . '"', $html );
		$this->assertStringNotContainsString( 'lwfw-2fa-passkey-button', $html );
	}

	public function test_correct_totp_sets_the_cookie_with_remember(): void {
		$_POST['rememberme'] = '1';
		$interceptor         = $this->interceptor();
		$token               = $this->login( 5, $interceptor );
		$_POST               = array();

		Actions\expectDone( 'lw_firewall_2fa_passed' )->once()->with( 5, 'totp' );
		Actions\expectDone( 'wp_login' )->never();

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertSame( array( array( 5, true ) ), $this->cookies );
		$this->assertSame( 'https://example.com/wp-admin/', end( $this->redirects ) );
		$this->assertNull( $this->store()->get( $token ), 'The token is single use.' );
	}

	public function test_without_remember_the_cookie_is_a_session_cookie(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertSame( array( array( 5, false ) ), $this->cookies );
	}

	public function test_the_same_code_twice_is_refused(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );
		$this->assertCount( 1, $this->cookies );

		// A new request (a new interceptor, as in WordPress).
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );
		$html  = $this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertCount( 1, $this->cookies, 'A replayed code must not open a second session.' );
		$this->assertStringContainsString( 'lwfw-2fa-form', $html );
	}

	public function test_a_wrong_code_counts_as_a_failed_login(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		Actions\expectDone( 'wp_login_failed' )->once()->with(
			'alice',
			\Mockery::on( static fn ( $e ) => $e instanceof \WP_Error && 'lwfw_2fa_invalid' === $e->get_error_code() )
		);

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => '000000' === $this->code() ? '111111' : '000000' ) );

		$this->assertSame( array(), $this->cookies );
		$this->assertSame( 1, $this->store()->attempts( $token ) );
	}

	public function test_five_wrong_answers_end_the_pending_login(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		for ( $i = 0; $i < 5; $i++ ) {
			$html = $this->submit( $interceptor, $token, array( 'lwfw_method' => 'recovery', 'lwfw_code' => 'nope-nope' ) );
		}

		$this->assertStringContainsString( 'https://example.com/wp-login.php', $html );
		$this->assertStringNotContainsString( 'lwfw-2fa-form', $html );
		$this->assertNull( $this->store()->get( $token ) );

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );
		$this->assertSame( array(), $this->cookies, 'A correct code after the lockout does not help.' );
	}

	public function test_a_bad_nonce_is_not_checked_and_not_counted(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		Actions\expectDone( 'wp_login_failed' )->never();
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code(), 'lwfw_2fa_nonce' => 'forged' ) );

		$this->assertSame( array(), $this->cookies );
		$this->assertSame( 0, $this->store()->attempts( $token ) );
	}

	public function test_a_recovery_code_works_once(): void {
		( new UserFactors( 5 ) )->set_recovery( array( password_hash( 'abcd2345', PASSWORD_DEFAULT ), password_hash( 'wxyz6789', PASSWORD_DEFAULT ) ) );
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'recovery', 'lwfw_code' => 'ABCD-2345' ) );

		$this->assertSame( array( array( 5, false ) ), $this->cookies );
		$this->assertCount( 1, ( new UserFactors( 5 ) )->recovery_hashes() );
	}

	public function test_an_unknown_token_shows_start_over(): void {
		$_REQUEST['token'] = str_repeat( 'a', 32 );

		$html = $this->until_halt( fn () => $this->interceptor()->handle_action() );

		$this->assertStringContainsString( 'https://example.com/wp-login.php', $html );
		$this->assertSame( 1, $this->halts );
	}

	public function test_a_token_from_another_ip_shows_start_over(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertSame( array(), $this->cookies );
	}

	public function test_failure_reasons(): void {
		$this->assertSame( 'twofa_failed', FailureLog::reason_for( 'totp' ) );
		$this->assertSame( 'twofa_failed', FailureLog::reason_for( 'recovery' ) );
		$this->assertSame( 'twofa_passkey_failed', FailureLog::reason_for( 'passkey' ) );
	}

	public function test_completing_does_not_re_enter_the_interceptor(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );
		$redirects   = count( $this->redirects );

		Actions\expectDone( 'lw_firewall_2fa_passed' )->once()->whenHappen(
			function () use ( $interceptor ) {
				// A plugin firing wp_login from here must not start a new pending login.
				$interceptor->on_wp_login( 'alice', $this->users[5] );
			}
		);
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertSame( $redirects + 1, count( $this->redirects ) );
		$this->assertSame( 1, $this->cleared, 'Only the password step cleared cookies.' );
	}

	// ---- passkey ------------------------------------------------------------

	private function give_passkey( int $user_id, string $raw_cred ): string {
		$cred = SoftAuthenticator::b64url( $raw_cred );
		( new UserFactors( $user_id ) )->add_passkey( new PasskeyRecord( hash( 'sha256', $cred ), $cred, 'PEM-' . $user_id, 0, 'Key', 100, 0 ) );
		return $cred;
	}

	/**
	 * @return array<string, string>
	 */
	private function assertion( string $raw_cred, int $user_id ): array {
		$b64 = static fn ( string $bin ): string => SoftAuthenticator::b64url( $bin );
		return array(
			'id'                => $b64( $raw_cred ),
			'clientDataJSON'    => $b64( (string) json_encode( array( 'type' => 'webauthn.get', 'origin' => 'https://example.com' ) ) ),
			'authenticatorData' => $b64( hash( 'sha256', 'example.com', true ) . chr( 5 ) . pack( 'N', 3 ) ),
			'signature'         => $b64( 'sig' ),
			'userHandle'        => $b64( (string) hex2bin( ( new UserFactors( $user_id ) )->user_handle() ) ),
		);
	}

	public function test_passkey_second_factor_uses_the_server_side_challenge(): void {
		$this->give_passkey( 5, 'alice-key' );
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		$html = $this->open( $interceptor, $token );
		$this->assertStringContainsString( 'lwfw-2fa-passkey-button', $html );
		$key = $this->store()->get( $token )['passkey_key'] ?? '';
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/D', $key );

		$this->submit(
			$interceptor,
			$token,
			array(
				'lwfw_method'  => 'passkey',
				'lwfw_passkey' => (string) json_encode( $this->assertion( 'alice-key', 5 ) ),
				'passkey_key'  => 'ignored',
			)
		);

		$this->assertSame( array( array( 5, false ) ), $this->cookies );
	}

	public function test_another_users_valid_passkey_is_rejected(): void {
		$this->give_passkey( 5, 'alice-key' );
		$this->give_passkey( 6, 'bob-key' );
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );
		$this->open( $interceptor, $token );

		Actions\expectDone( 'wp_login_failed' )->once();
		$this->submit(
			$interceptor,
			$token,
			array(
				'lwfw_method'  => 'passkey',
				'lwfw_passkey' => (string) json_encode( $this->assertion( 'bob-key', 6 ) ),
			)
		);

		$this->assertSame( array(), $this->cookies );
		$this->assertArrayNotHasKey( 'processGet', $this->lib->calls );
	}

	public function test_a_passkey_without_a_server_side_challenge_is_rejected(): void {
		$this->give_passkey( 5, 'alice-key' );
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		// No GET first: the pending record holds no challenge key.
		$this->submit(
			$interceptor,
			$token,
			array(
				'lwfw_method'  => 'passkey',
				'lwfw_passkey' => (string) json_encode( $this->assertion( 'alice-key', 5 ) ),
			)
		);

		$this->assertSame( array(), $this->cookies );
	}

	// ---- fix round 1 --------------------------------------------------------

	public function test_a_login_outside_wp_signon_still_loses_its_session(): void {
		$interceptor = $this->interceptor();

		// A custom handler: wp_set_auth_cookie() (cookie already sent) + do_action( 'wp_login' ).
		$interceptor->capture_cookie( 'cookie', 0, 0, 5, 'secure_auth', 'tok-custom' );
		$interceptor->capture_cookie( 'cookie', 0, 0, 5, 'logged_in', 'tok-custom' );
		$this->login( 5, $interceptor );

		$this->assertSame( array( 5 => array( 'tok-custom' ) ), \WP_Session_Tokens::$destroyed );
		$this->assertSame( 1, $this->cleared );
	}

	public function test_cookie_re_auth_of_a_signed_in_user_is_not_challenged(): void {
		$this->cookie_user = 5;
		$interceptor       = $this->interceptor();
		$this->signon->start( '', '' );

		$this->assertTrue( $interceptor->filter_send_cookies( true, 0, 0, 5, 'auth', 'tok-refresh' ) );
		$interceptor->on_wp_login( 'alice', $this->users[5] );

		$this->assertSame( 0, $this->cleared );
		$this->assertSame( array(), $this->redirects );
		$this->assertSame( array(), \WP_Session_Tokens::$destroyed );
	}

	public function test_empty_credentials_without_the_same_cookie_user_are_challenged(): void {
		$this->cookie_user = 6;
		$interceptor       = $this->interceptor();
		$this->signon->start( '', '' );

		$this->login( 5, $interceptor );

		$this->assertSame( 1, $this->cleared, 'Only a cookie of the same user skips the challenge.' );
	}

	public function test_redirect_to_the_login_screen_does_not_loop(): void {
		$_REQUEST['redirect_to'] = 'https://example.com/wp-login.php';
		$interceptor             = $this->interceptor();
		$token                   = $this->login( 5, $interceptor );

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertSame( 'https://example.com/wp-admin/', end( $this->redirects ) );
	}

	public function test_the_sixth_attempt_is_refused_even_with_the_right_code(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		// Five parallel requests already claimed their attempts.
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertTrue( $this->store()->begin_attempt( $token ) );
		}

		$html = $this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertSame( array(), $this->cookies );
		$this->assertStringNotContainsString( 'lwfw-2fa-form', $html );
		$this->assertNull( $this->store()->get( $token ) );
	}

	public function test_ten_failures_throttle_the_account(): void {
		for ( $round = 0; $round < 2; $round++ ) {
			$interceptor = $this->interceptor();
			$token       = $this->login( 5, $interceptor );
			for ( $i = 0; $i < 5; $i++ ) {
				$this->submit( $interceptor, $token, array( 'lwfw_method' => 'recovery', 'lwfw_code' => 'nope-nope' ) );
			}
		}
		$this->assertTrue( $this->throttle->is_blocked( 5 ) );

		// The password step no longer opens a pending login.
		$redirects = count( $this->redirects );
		$html      = $this->until_halt( fn () => $this->interceptor()->on_wp_login( 'alice', $this->users[5] ) );
		$this->assertSame( $redirects, count( $this->redirects ) );
		$this->assertStringContainsString( 'Start over', $html );
	}

	public function test_a_throttled_account_cannot_answer_an_existing_token(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->throttle->claim( 5 );
			$this->throttle->record_failure( 5 );
		}

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertSame( array(), $this->cookies );
		$this->assertSame( 0, $this->store()->attempts( $token ), 'Not even checked.' );
	}

	public function test_an_unreadable_totp_secret_still_challenges_and_offers_recovery(): void {
		( new UserFactors( 5 ) )->set_recovery( array( password_hash( 'abcd2345', PASSWORD_DEFAULT ) ) );
		Functions\when( 'wp_salt' )->justReturn( 'rotated' );
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		$this->assertSame( 1, $this->cleared, 'Fail closed.' );
		$html = $this->open( $interceptor, $token );
		$this->assertStringContainsString( 'lwfw-2fa-recovery-code', $html );
		$this->assertStringNotContainsString( 'one-time-code', $html );
	}

	public function test_no_usable_method_says_so_instead_of_a_dead_field(): void {
		Functions\when( 'wp_salt' )->justReturn( 'rotated' );
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		$html = $this->open( $interceptor, $token );

		$this->assertStringNotContainsString( 'lwfw-2fa-form', $html );
		$this->assertStringContainsString( 'https://example.com/wp-login.php', $html );
	}

	public function test_no_recovery_link_without_recovery_codes(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );

		$this->assertStringNotContainsString( 'mode=recovery', $this->open( $interceptor, $token ) );

		$_GET['mode'] = 'recovery';
		$this->assertStringContainsString( 'one-time-code', $this->until_halt( fn () => $interceptor->handle_action() ) );
	}

	public function test_wp_login_with_odd_arguments_is_ignored(): void {
		$interceptor = $this->interceptor();
		$interceptor->on_wp_login( 'alice' );
		$interceptor->on_wp_login( 'alice', 'not-a-user' );

		$this->assertSame( 0, $this->cleared );
	}

	public function test_remember_and_secure_come_from_the_signon(): void {
		$interceptor = $this->interceptor();
		$this->signon->start( 'alice', 'pw' );
		$this->signon->capture( true, array( 'remember' => true ) );
		$token = $this->login( 5, $interceptor );

		$record = $this->store()->get( $token );
		$this->assertTrue( $record['remember'] ?? null );
		$this->assertTrue( $record['secure'] ?? null );

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );
		$this->assertSame( array( array( 5, true ) ), $this->cookies );
		$this->assertSame( array( true ), $this->secure );
	}

	public function test_hooks_are_registered_at_the_right_priorities(): void {
		$interceptor = $this->interceptor();
		$interceptor->register();

		$this->assertSame( PHP_INT_MAX, has_filter( 'send_auth_cookies', array( $interceptor, 'filter_send_cookies' ) ) );
		$this->assertNotFalse( has_action( 'set_logged_in_cookie', array( $interceptor, 'capture_cookie' ) ) );
		$this->assertNotFalse( has_action( 'set_auth_cookie', array( $interceptor, 'capture_cookie' ) ) );
		$this->assertSame( 1, has_action( 'wp_login', array( $interceptor, 'on_wp_login' ) ) );
	}

	// ---- fix round 3 --------------------------------------------------------

	public function test_parallel_answers_over_many_tokens_share_the_account_budget(): void {
		$tokens = array();
		for ( $i = 0; $i < 3; $i++ ) {
			$tokens[] = $this->login( 5, $this->interceptor() );
		}

		// Ten answers already in flight (claimed, not yet failed) over these tokens.
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->assertTrue( $this->throttle->claim( 5 ) );
		}

		$html = $this->submit( $this->interceptor(), $tokens[2], array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertSame( array(), $this->cookies, 'The eleventh answer is not checked, even a right one.' );
		$this->assertSame( 0, ( new UserFactors( 5 ) )->totp_last_step(), 'The code was never verified.' );
		$this->assertStringNotContainsString( 'lwfw-2fa-form', $html );
		$this->assertTrue( $this->throttle->is_blocked( 5 ) );
	}

	public function test_a_right_answer_resets_the_account_budget(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'recovery', 'lwfw_code' => 'nope-nope' ) );
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );

		$this->assertCount( 1, $this->cookies );
		$this->assertSame( 0, $this->storage->count( 5, FailureThrottle::META_KEY, FailureThrottle::WINDOW ) );
	}

	public function test_the_tracker_reads_the_final_username(): void {
		$this->signon->register();

		$this->assertSame( PHP_INT_MAX, has_action( 'wp_authenticate', array( $this->signon, 'start' ) ) );

		// A plugin at a normal priority rewrote "alice@example.com" to "alice" before us.
		$this->signon->start( 'alice', 'pw' );
		$this->assertTrue( $this->signon->accepts_password_for( 'alice' ) );
		$this->assertFalse( $this->signon->accepts_password_for( 'alice@example.com' ) );
	}

	// ---- remember this device -----------------------------------------------

	/**
	 * @param array<int, array{0: string, 1: string, 2: array<string, mixed>}> $sink Captured cookies.
	 */
	private function remember_device( array &$sink ): RememberDevice {
		return new RememberDevice(
			fn (): int => $this->now,
			static function ( string $name, string $value, array $options ) use ( &$sink ): void {
				$sink[] = array( $name, $value, $options );
			}
		);
	}

	public function test_the_checkbox_shows_only_when_remember_days_is_set(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 5, $interceptor );
		$this->assertStringNotContainsString( 'lwfw_remember_device', $this->open( $interceptor, $token ) );

		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false, 'twofa_remember_days' => 14 ) ) );
		$html = $this->open( $interceptor, $token );
		$this->assertStringContainsString( 'name="lwfw_remember_device"', $html );
		$this->assertStringContainsString( 'Remember this device for 14 days', $html );
	}

	public function test_a_ticked_box_issues_the_cookie_and_the_next_login_skips_the_challenge(): void {
		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false, 'twofa_remember_days' => 14 ) ) );
		$sink        = array();
		$interceptor = $this->interceptor( array(), $this->remember_device( $sink ) );
		$token       = $this->login( 5, $interceptor );

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code(), 'lwfw_remember_device' => '1' ) );

		$this->assertCount( 1, $sink );
		$this->assertSame( 14 * 86400 + $this->now, $sink[0][2]['expires'] );
		$_COOKIE[ $sink[0][0] ] = $sink[0][1];
		$this->assertFalse( $interceptor->should_challenge( $this->users[5] ) );
		$this->assertFalse( $interceptor->should_challenge( $this->users[6] ), 'No factors, no challenge.' );
		unset( $_COOKIE[ $sink[0][0] ] );
		$this->assertTrue( $interceptor->should_challenge( $this->users[5] ) );
	}

	public function test_an_unticked_box_or_zero_days_issues_nothing(): void {
		$sink        = array();
		$interceptor = $this->interceptor( array(), $this->remember_device( $sink ) );
		$token       = $this->login( 5, $interceptor );
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code(), 'lwfw_remember_device' => '1' ) );
		$this->assertSame( array(), $sink, 'Days = 0: nothing is issued.' );

		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false, 'twofa_remember_days' => 14 ) ) );
		$this->now += 60;
		$token = $this->login( 5, $interceptor );
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code() ) );
		$this->assertSame( array(), $sink, 'Box not ticked: nothing is issued.' );
	}

	public function test_no_remember_cookie_after_a_wrong_code(): void {
		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false, 'twofa_remember_days' => 14 ) ) );
		$sink        = array();
		$interceptor = $this->interceptor( array(), $this->remember_device( $sink ) );
		$token       = $this->login( 5, $interceptor );

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => '000000', 'lwfw_remember_device' => '1' ) );

		$this->assertSame( array(), $sink );
		$this->assertSame( array(), $this->cookies );
	}

	public function test_no_remember_cookie_with_an_expired_token(): void {
		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false, 'twofa_remember_days' => 14 ) ) );
		$sink        = array();
		$interceptor = $this->interceptor( array(), $this->remember_device( $sink ) );
		$token       = $this->login( 5, $interceptor );
		$code        = $this->code();
		$this->now  += 3600;

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $code, 'lwfw_remember_device' => '1' ) );

		$this->assertSame( array(), $sink );
		$this->assertSame( array(), $this->cookies );
	}

	public function test_no_remember_cookie_for_a_throttled_account(): void {
		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false, 'twofa_remember_days' => 14 ) ) );
		$sink        = array();
		$interceptor = $this->interceptor( array(), $this->remember_device( $sink ) );
		$token       = $this->login( 5, $interceptor );
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->throttle->claim( 5 );
			$this->throttle->record_failure( 5 );
		}

		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code(), 'lwfw_remember_device' => '1' ) );

		$this->assertSame( array(), $sink );
		$this->assertSame( array(), $this->cookies );
	}
}
