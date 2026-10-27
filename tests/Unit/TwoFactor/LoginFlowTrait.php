<?php
/**
 * Shared scaffolding of the login-flow tests (challenge and enrollment).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\Support\FakeWpdb;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\FakeWebAuthn;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\PasskeyStubTrait;
use LightweightPlugins\Firewall\TwoFactor\AttemptCounter;
use LightweightPlugins\Firewall\TwoFactor\ChallengePage;
use LightweightPlugins\Firewall\TwoFactor\Enforcement;
use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\LoginInterceptor;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
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
 * Users 5 (alice, TOTP), 6 (bob) and 7 (carol); the using class defines SECRET.
 */
trait LoginFlowTrait {

	use PasskeyStubTrait;
	use UserMetaStubTrait;

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

	/**
	 * Secure flags passed to wp_set_auth_cookie.
	 *
	 * @var array<int, mixed>
	 */
	private array $secure = array();

	private int $halts = 0;

	/**
	 * Users by ID.
	 *
	 * @var array<int, \WP_User>
	 */
	private array $users = array();

	private FakeWebAuthn $lib;

	private AttemptCounter $storage;

	private SignonTracker $signon;

	private FailureThrottle $throttle;

	/**
	 * User of the browser's valid logged-in cookie (0 = none).
	 */
	private int $cookie_user = 0;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_passkey_wp();
		$this->stub_user_meta();
		$this->stub_wp();
		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false ) ) );

		$this->lib      = new FakeWebAuthn();
		$this->storage  = new AttemptCounter( fn (): int => $this->now, new FakeWpdb() );
		Functions\when( 'wp_cache_delete' )->justReturn( true );
		$this->signon   = new SignonTracker( fn (): int => $this->cookie_user );
		$this->throttle = new FailureThrottle( $this->storage );
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
		Functions\when( 'sanitize_user' )->alias( static fn ( $u ) => trim( strip_tags( (string) $u ) ) );
		Functions\when( 'is_ssl' )->justReturn( false );
		Functions\when( 'wp_set_auth_cookie' )->alias(
			function ( $id, $remember = false, $secure = '' ) {
				$this->cookies[] = array( (int) $id, (bool) $remember );
				$this->secure[]  = $secure;
			}
		);
		Functions\when( 'wp_set_current_user' )->justReturn( null );
		Functions\when( 'wp_check_password' )->alias( static fn ( $plain, $hash ) => password_verify( (string) $plain, (string) $hash ) );
	}

	/**
	 * @param array<string, bool> $flags Request flags.
	 */
	private function interceptor( array $flags = array(), ?RememberDevice $remember = null ): LoginInterceptor {
		$clock = fn (): int => $this->now;

		return new LoginInterceptor(
			new PendingLogin( null, $clock, $this->storage ),
			new SecondFactorVerifier( new PasskeyService( $this->lib ), $clock ),
			new ChallengePage(),
			new RequestContext( $flags ),
			function (): void {
				++$this->halts;
				throw new \RuntimeException( 'halt' );
			},
			$this->signon,
			$this->throttle,
			$remember,
			new Enforcement( $clock )
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
		return new PendingLogin( null, fn (): int => $this->now, $this->storage );
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
}
