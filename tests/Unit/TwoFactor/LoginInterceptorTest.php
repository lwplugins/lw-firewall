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
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\FakeWebAuthn;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\PasskeyStubTrait;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\SoftAuthenticator;
use LightweightPlugins\Firewall\TwoFactor\ChallengeController;
use LightweightPlugins\Firewall\TwoFactor\ChallengePage;
use LightweightPlugins\Firewall\TwoFactor\LoginInterceptor;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\PendingLogin;
use LightweightPlugins\Firewall\TwoFactor\RequestContext;
use LightweightPlugins\Firewall\TwoFactor\SecondFactorVerifier;
use LightweightPlugins\Firewall\TwoFactor\Totp;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpError.php';
require_once dirname( __DIR__ ) . '/Support/WpUser.php';
require_once dirname( __DIR__ ) . '/Support/WpSessionTokens.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\LoginInterceptor
 * @covers \LightweightPlugins\Firewall\TwoFactor\LoginRequest
 * @covers \LightweightPlugins\Firewall\TwoFactor\SecondFactorVerifier
 * @covers \LightweightPlugins\Firewall\TwoFactor\ChallengePage
 * @covers \LightweightPlugins\Firewall\TwoFactor\ChallengeController
 * @covers \LightweightPlugins\Firewall\TwoFactor\PendingLogin
 */
final class LoginInterceptorTest extends MonkeyTestCase {

	use PasskeyStubTrait;
	use UserMetaStubTrait;

	private const SECRET = 'JBSWY3DPEHPK3PXP';

	private int $now = 1700000000;

	/**
	 * Captured wp_safe_redirect targets.
	 *
	 * @var string[]
	 */
	private array $redirects = array();

	/**
	 * Captured wp_set_auth_cookie calls.
	 *
	 * @var array<int, array{0: int, 1: bool}>
	 */
	private array $cookies = array();

	private int $cleared = 0;

	private int $halts = 0;

	/**
	 * Users by ID.
	 *
	 * @var array<int, \WP_User>
	 */
	private array $users = array();

	private FakeWebAuthn $lib;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_passkey_wp();
		$this->stub_user_meta();
		$this->stub_wp();
		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false ) ) );

		$this->lib   = new FakeWebAuthn();
		$this->users = array(
			5 => new \WP_User( 5, 'alice' ),
			6 => new \WP_User( 6, 'bob' ),
			7 => new \WP_User( 7, 'carol' ),
		);
		( new UserFactors( 5 ) )->save_totp( self::SECRET );
		\WP_Session_Tokens::$destroyed = array();
		$_SERVER['REMOTE_ADDR']        = '203.0.113.7';
		$_SERVER['REQUEST_METHOD']     = 'GET';
		$_POST                         = array();
		$_GET                          = array();
		$_REQUEST                      = array();
	}

	protected function tearDown(): void {
		$_POST    = array();
		$_GET     = array();
		$_REQUEST = array();
		unset( $_SERVER['REMOTE_ADDR'], $_SERVER['REQUEST_METHOD'] );
		parent::tearDown();
	}

	private function stub_wp(): void {
		Functions\stubEscapeFunctions();
		Functions\when( 'wp_salt' )->justReturn( 'salt' );
		Functions\when( 'wp_unslash' )->alias( static fn ( $v ) => is_string( $v ) ? stripslashes( $v ) : $v );
		Functions\when( 'sanitize_text_field' )->alias( static fn ( $v ) => trim( (string) $v ) );
		Functions\when( 'sanitize_key' )->alias( static fn ( $v ) => (string) preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $v ) ) );
		Functions\when( 'sanitize_url' )->alias( static fn ( $v ) => (string) $v );
		Functions\when( 'admin_url' )->alias( static fn ( $path = '' ) => 'https://example.com/wp-admin/' . $path );
		Functions\when( 'wp_login_url' )->justReturn( 'https://example.com/wp-login.php' );
		Functions\when( 'wp_validate_redirect' )->alias(
			static fn ( $url, $fallback = '' ) => str_starts_with( (string) $url, 'https://example.com/' ) || str_starts_with( (string) $url, '/' ) ? (string) $url : $fallback
		);
		Functions\when( 'add_query_arg' )->alias( static fn ( $args, $url ) => $url . '?' . http_build_query( $args ) );
		Functions\when( 'user_can' )->justReturn( true );
		Functions\when( 'nocache_headers' )->justReturn( null );
		Functions\when( 'login_header' )->justReturn( null );
		Functions\when( 'login_footer' )->justReturn( null );
		Functions\when( 'wp_nonce_field' )->justReturn( '' );
		Functions\when( 'wp_enqueue_script' )->justReturn( null );
		Functions\when( 'wp_verify_nonce' )->alias( static fn ( $nonce, $action ) => 'nonce:' . $action === $nonce ? 1 : false );
		Functions\when( 'get_userdata' )->alias( fn ( $id ) => $this->users[ (int) $id ] ?? false );
		Functions\when( 'wp_safe_redirect' )->alias(
			function ( $url ) {
				$this->redirects[] = (string) $url;
				return true;
			}
		);
		Functions\when( 'wp_clear_auth_cookie' )->alias(
			function () {
				++$this->cleared;
			}
		);
		Functions\when( 'wp_set_auth_cookie' )->alias(
			function ( $id, $remember = false ) {
				$this->cookies[] = array( (int) $id, (bool) $remember );
			}
		);
		Functions\when( 'wp_set_current_user' )->justReturn( null );
		Functions\when( 'wp_check_password' )->alias( static fn ( $plain, $hash ) => password_verify( (string) $plain, (string) $hash ) );
	}

	/**
	 * @param array<string, bool> $flags Request flags.
	 */
	private function interceptor( array $flags = array() ): LoginInterceptor {
		$clock = fn (): int => $this->now;

		return new LoginInterceptor(
			new PendingLogin( null, $clock ),
			new SecondFactorVerifier( new PasskeyService( $this->lib ), $clock ),
			new ChallengePage(),
			new RequestContext( $flags ),
			function (): void {
				++$this->halts;
				throw new \RuntimeException( 'halt' );
			}
		);
	}

	/**
	 * Run a callable that ends in a halt.
	 */
	private function until_halt( callable $fn ): string {
		ob_start();
		try {
			$fn();
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'halt', $e->getMessage() );
		}
		return (string) ob_get_clean();
	}

	/**
	 * Password step for a user; returns the pending token.
	 */
	private function login( int $user_id, LoginInterceptor $interceptor ): string {
		$this->until_halt( fn () => $interceptor->on_wp_login( $this->users[ $user_id ]->user_login, $this->users[ $user_id ] ) );
		$url = (string) end( $this->redirects );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $query );
		return (string) ( $query['token'] ?? '' );
	}

	/**
	 * Post an answer to the challenge.
	 *
	 * @param array<string, string> $fields Form fields.
	 */
	private function submit( LoginInterceptor $interceptor, string $token, array $fields ): string {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_POST                     = $fields + array(
			'token'          => $token,
			'lwfw_2fa_nonce' => 'nonce:lw_firewall_2fa_' . $token,
		);
		$_REQUEST                  = $_POST;
		return $this->until_halt( fn () => $interceptor->handle_action() );
	}

	private function store(): PendingLogin {
		return new PendingLogin( null, fn (): int => $this->now );
	}

	private function open( LoginInterceptor $interceptor, string $token ): string {
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_POST                     = array();
		$_REQUEST                  = array( 'token' => $token );
		return $this->until_halt( fn () => $interceptor->handle_action() );
	}

	private function code(): string {
		return Totp::code_at( self::SECRET, intdiv( $this->now, 30 ) );
	}

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

		$interceptor->on_signon_start();
		$this->assertFalse( $interceptor->filter_send_cookies( true, 0, 0, 5, 'secure_auth', 'tok-1' ) );
		$this->assertTrue( $interceptor->filter_send_cookies( true, 0, 0, 6, 'auth', 'tok-bob' ), 'A user without factors keeps the cookie.' );
		$this->assertTrue( $interceptor->filter_send_cookies( true, 0, 0, 0, '', '' ), 'Clearing cookies is never blocked.' );

		$this->login( 5, $interceptor );

		$this->assertSame( array( 5 => array( 'tok-1' ) ), \WP_Session_Tokens::$destroyed );
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
		$this->assertSame( 1, $this->store()->get( $token )['attempts'] ?? null );
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
		$this->assertSame( 0, $this->store()->get( $token )['attempts'] ?? null );
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
		$this->assertSame( 'twofa_failed', ChallengeController::failure_reason( 'totp' ) );
		$this->assertSame( 'twofa_failed', ChallengeController::failure_reason( 'recovery' ) );
		$this->assertSame( 'twofa_passkey_failed', ChallengeController::failure_reason( 'passkey' ) );
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
}
