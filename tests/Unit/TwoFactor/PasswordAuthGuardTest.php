<?php
/**
 * Tests for the password-only sign-in guard.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\FakeWpdb;
use LightweightPlugins\Firewall\TwoFactor\AttemptCounter;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\PasswordAuthGuard;
use LightweightPlugins\Firewall\TwoFactor\RequestContext;
use LightweightPlugins\Firewall\TwoFactor\SignonTracker;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpError.php';
require_once dirname( __DIR__ ) . '/Support/WpUser.php';

require_once dirname( __DIR__ ) . '/Support/FakeWpdb.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\PasswordAuthGuard
 * @covers \LightweightPlugins\Firewall\TwoFactor\RequestContext
 * @covers \LightweightPlugins\Firewall\TwoFactor\SignonTracker
 * @covers \LightweightPlugins\Firewall\TwoFactor\FailureThrottle
 */
final class PasswordAuthGuardTest extends MonkeyTestCase {

	use UserMetaStubTrait;

	private \WP_User $alice;

	private \WP_User $bob;

	private SignonTracker $signon;

	private FailureThrottle $throttle;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_user_meta();
		Functions\stubTranslationFunctions();
		Functions\when( 'wp_strip_all_tags' )->alias( static fn ( $s ) => strip_tags( (string) $s ) );
		Functions\when( 'sanitize_text_field' )->alias( static fn ( $v ) => trim( (string) $v ) );
		Functions\when( 'sanitize_url' )->alias( static fn ( $v ) => (string) $v );
		Functions\when( 'wp_unslash' )->alias( static fn ( $v ) => $v );
		Functions\when( 'sanitize_user' )->alias( static fn ( $u ) => trim( strip_tags( (string) $u ) ) );
		Functions\when( 'is_email' )->alias( static fn ( $s ) => str_contains( (string) $s, '@' ) );
		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false ) ) );
		$this->alice = new \WP_User( 5, 'alice' );
		$this->bob   = new \WP_User( 6, 'bob' );
		Functions\when( 'get_user_by' )->alias(
			fn ( $field, $value ) => array( 'alice' => $this->alice, 'bob' => $this->bob )[ $value ] ?? false
		);
		( new UserFactors( 5 ) )->add_passkey( new PasskeyRecord( hash( 'sha256', 'cred' ), 'cred', 'PEM', 0, 'Key', 1, 0 ) );
		$this->signon   = new SignonTracker( static fn (): int => 0 );
		Functions\when( 'wp_cache_delete' )->justReturn( true );
		$this->throttle = new FailureThrottle( new AttemptCounter( static fn (): int => 1700000000, new FakeWpdb() ) );
	}

	/**
	 * @param array<string, bool> $flags Request flags.
	 */
	private function guard( array $flags = array() ): PasswordAuthGuard {
		return new PasswordAuthGuard( new RequestContext( $flags ), $this->signon, $this->throttle );
	}

	private function assert_refused( $result, string $code = PasswordAuthGuard::ERROR_CODE ): void {
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( $code, $result->get_error_code() );
	}

	public function test_xmlrpc_password_of_a_two_factor_user_is_refused(): void {
		$this->assert_refused( $this->guard( array( 'xmlrpc' => true ) )->filter( $this->alice, 'alice', 'pw' ) );
	}

	public function test_without_two_factor_every_path_passes(): void {
		$this->assertSame( $this->bob, $this->guard( array( 'xmlrpc' => true ) )->filter( $this->bob, 'bob', 'pw' ) );
		$this->assertSame( $this->bob, $this->guard()->filter( $this->bob, 'bob', 'pw' ) );
	}

	public function test_rest_basic_auth_with_the_real_password_is_refused_even_without_rest_request(): void {
		// A password-auth plugin authenticating at determine_current_user: no
		// wp_signon(), and REST_REQUEST not yet defined.
		$this->assert_refused( $this->guard()->filter( $this->alice, 'alice', 'pw' ) );
		$this->assert_refused( $this->guard( array( 'rest' => true ) )->filter( $this->alice, 'alice', 'pw' ) );
	}

	public function test_ajax_signon_is_refused(): void {
		$this->signon->start( 'alice', 'pw' );

		$this->assert_refused( $this->guard( array( 'ajax' => true ) )->filter( $this->alice, 'alice', 'pw' ) );
	}

	public function test_interactive_wp_signon_passes_to_the_interceptor(): void {
		$this->signon->start( 'alice', 'pw' );

		$this->assertSame( $this->alice, $this->guard()->filter( $this->alice, 'alice', 'pw' ) );

		$this->signon->finish();
		$this->assert_refused( $this->guard()->filter( $this->alice, 'alice', 'pw' ), PasswordAuthGuard::ERROR_CODE );
	}

	public function test_wp_cli_is_unaffected(): void {
		$this->assertSame( $this->alice, $this->guard( array( 'cli' => true ) )->filter( $this->alice, 'alice', 'pw' ) );
	}

	public function test_errors_and_nulls_pass_through(): void {
		$error = new \WP_Error( 'incorrect_password' );

		$this->assertSame( $error, $this->guard( array( 'xmlrpc' => true ) )->filter( $error, 'alice', 'pw' ) );
		$this->assertNull( $this->guard()->filter( null, '', '' ) );
	}

	public function test_an_application_password_of_the_same_user_passes(): void {
		$guard = $this->guard( array( 'xmlrpc' => true ) );
		$guard->note_app_password( $this->alice );

		$this->assertSame( $this->alice, $guard->filter( $this->alice, 'alice', 'xxxx xxxx' ) );
	}

	public function test_another_users_application_password_does_not_open_the_gate(): void {
		$guard = $this->guard( array( 'xmlrpc' => true ) );
		$guard->note_app_password( $this->bob );

		$this->assert_refused( $guard->filter( $this->alice, 'alice', 'pw' ) );
	}

	public function test_a_throttled_account_is_refused_right_password_or_not(): void {
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->throttle->claim( 5 );
			$this->throttle->record_failure( 5 );
		}
		$this->signon->start( 'alice', 'pw' );

		$this->assert_refused( $this->guard()->filter( $this->alice, 'alice', 'pw' ), PasswordAuthGuard::THROTTLED_CODE );
		$this->assert_refused( $this->guard()->filter( new \WP_Error( 'incorrect_password' ), 'alice', 'wrong' ), PasswordAuthGuard::THROTTLED_CODE );
		$this->assertSame( $this->bob, $this->guard()->filter( $this->bob, 'bob', 'pw' ) );
	}

	public function test_throttle_blocks_after_ten_failures(): void {
		for ( $i = 1; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->assertFalse( ( $this->throttle->claim( 5 ) && $this->throttle->record_failure( 5 ) ) );
		}
		$this->assertFalse( $this->throttle->is_blocked( 5 ) );
		$this->assertTrue( ( $this->throttle->claim( 5 ) && $this->throttle->record_failure( 5 ) ) );
		$this->assertTrue( $this->throttle->is_blocked( 5 ) );
		$this->assertFalse( $this->throttle->is_blocked( 6 ) );
	}

	public function test_application_passwords_can_be_switched_off_for_two_factor_users(): void {
		$guard = $this->guard();

		$this->assertFalse( $guard->filter_app_passwords( true, $this->alice ) );
		$this->assertTrue( $guard->filter_app_passwords( true, $this->bob ) );
		$this->assertFalse( $guard->filter_app_passwords( false, $this->bob ) );
	}

	public function test_register_wires_the_hooks(): void {
		$guard = $this->guard();
		$guard->register( true );

		$this->assertSame( PasswordAuthGuard::PRIORITY, has_filter( 'authenticate', array( $guard, 'filter' ) ) );
		$this->assertNotFalse( has_action( 'application_password_did_authenticate', array( $guard, 'note_app_password' ) ) );
		$this->assertNotFalse( has_filter( 'wp_is_application_passwords_available_for_user', array( $guard, 'filter_app_passwords' ) ) );
	}

	public function test_app_password_filter_is_off_by_default(): void {
		$guard = $this->guard();
		$guard->register( false );

		$this->assertFalse( has_filter( 'wp_is_application_passwords_available_for_user', array( $guard, 'filter_app_passwords' ) ) );
	}

	public function test_signon_tracker_lifecycle(): void {
		$tracker = new SignonTracker( static fn (): int => 5 );
		$this->assertFalse( $tracker->in_progress() );

		$tracker->start( 'alice', 'pw' );
		$this->assertTrue( $tracker->in_progress() );
		$this->assertSame( 0, $tracker->cookie_user(), 'Credentials given: no cookie re-auth.' );
		$this->assertTrue( $tracker->capture( true, array( 'remember' => true ) ) );
		$this->assertTrue( $tracker->remember() );
		$this->assertTrue( $tracker->secure() );

		$tracker->finish();
		$this->assertFalse( $tracker->in_progress() );
		$this->assertNull( $tracker->remember() );

		$tracker->start( '', '' );
		$this->assertSame( 5, $tracker->cookie_user() );
	}

	public function test_request_context_reads_flags(): void {
		$this->assertTrue( ( new RequestContext( array() ) )->is_interactive() );
		$this->assertFalse( ( new RequestContext( array( 'cron' => true ) ) )->is_interactive() );
		$this->assertFalse( ( new RequestContext( array( 'cli' => true ) ) )->is_interactive() );
	}

	public function test_request_context_detects_the_real_request(): void {
		Functions\when( 'wp_doing_ajax' )->justReturn( false );
		Functions\when( 'wp_doing_cron' )->justReturn( true );

		$this->assertFalse( ( new RequestContext() )->is_interactive() );
	}

	// ---- fix round 2 --------------------------------------------------------

	public function test_the_password_result_must_match_the_tracked_username(): void {
		$this->signon->start( 'bob', 'pw' );

		$this->assert_refused( $this->guard()->filter( $this->alice, 'alice', 'pw' ) );
		$this->assertSame( $this->bob, $this->guard()->filter( $this->bob, 'bob', 'pw' ) );
	}

	public function test_an_empty_credential_signon_is_not_a_password_signon(): void {
		$this->signon->start( '', '' );

		$this->assertFalse( $this->signon->accepts_password_for( '' ) );
		$this->assert_refused( $this->guard()->filter( $this->alice, '', '' ) );
	}

	public function test_core_cookie_re_auth_of_the_same_user_passes(): void {
		$tracker = new SignonTracker( static fn (): int => 5 );
		$tracker->start( '', '' );
		$guard = new PasswordAuthGuard( new RequestContext( array() ), $tracker, $this->throttle );

		$this->assertSame( $this->alice, $guard->filter( $this->alice, '', '' ) );
	}

	public function test_the_window_closes_on_an_authenticate_error(): void {
		foreach ( array( 'empty_username', 'empty_password', 'incorrect_password' ) as $code ) {
			$this->signon->start( 'alice', 'pw' );
			$error = new \WP_Error( $code );

			$this->assertSame( $error, $this->signon->close_on_error( $error ) );
			$this->assertFalse( $this->signon->in_progress(), $code );
			$this->assert_refused( $this->guard()->filter( $this->alice, 'alice', 'pw' ) );
		}

		$this->signon->start( 'alice', 'pw' );
		$this->signon->close_on_error( null );
		$this->assertFalse( $this->signon->in_progress(), 'A null result closes too.' );

		$this->signon->start( 'alice', 'pw' );
		$this->assertSame( $this->alice, $this->signon->close_on_error( $this->alice ) );
		$this->assertTrue( $this->signon->in_progress(), 'Success stays open until wp_login.' );
	}

	public function test_tracker_closes_at_the_end_of_authenticate(): void {
		$this->signon->register();

		$this->assertSame( PHP_INT_MAX, has_filter( 'authenticate', array( $this->signon, 'close_on_error' ) ) );
		$this->assertSame( PHP_INT_MAX, has_action( 'wp_login', array( $this->signon, 'finish' ) ) );
		$this->assertSame( PHP_INT_MAX, has_action( 'wp_login_failed', array( $this->signon, 'finish' ) ) );
	}

	public function test_a_throttled_account_keeps_its_xmlrpc_application_password(): void {
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->throttle->claim( 5 );
			$this->throttle->record_failure( 5 );
		}
		$guard = $this->guard( array( 'xmlrpc' => true ) );

		$this->assert_refused( $guard->filter( $this->alice, 'alice', 'pw' ), PasswordAuthGuard::THROTTLED_CODE );

		$guard->note_app_password( $this->alice );
		$this->assertSame( $this->alice, $guard->filter( $this->alice, 'alice', 'xxxx xxxx' ) );
	}

	public function test_a_throttled_account_keeps_its_rest_application_password(): void {
		// REST application passwords authenticate in determine_current_user, never
		// through `authenticate`, and the availability filter ignores the throttle.
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->throttle->claim( 5 );
			$this->throttle->record_failure( 5 );
		}
		$guard = $this->guard( array( 'rest' => true ) );
		$guard->register( false );

		$this->assertFalse( has_filter( 'determine_current_user' ) );
		$this->assertFalse( has_filter( 'wp_is_application_passwords_available_for_user' ) );
		$this->assertTrue( $guard->filter_app_passwords( true, $this->bob ) );
	}
}
