<?php
/**
 * Tests for the password-only sign-in guard (XML-RPC, REST, AJAX).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\PasswordAuthGuard;
use LightweightPlugins\Firewall\TwoFactor\RequestContext;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpError.php';
require_once dirname( __DIR__ ) . '/Support/WpUser.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\PasswordAuthGuard
 * @covers \LightweightPlugins\Firewall\TwoFactor\RequestContext
 */
final class PasswordAuthGuardTest extends MonkeyTestCase {

	use UserMetaStubTrait;

	private \WP_User $alice;

	private \WP_User $bob;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_user_meta();
		Functions\stubTranslationFunctions();
		Functions\when( 'wp_strip_all_tags' )->alias( static fn ( $s ) => strip_tags( (string) $s ) );
		$this->alice = new \WP_User( 5, 'alice' );
		$this->bob   = new \WP_User( 6, 'bob' );
		( new UserFactors( 5 ) )->add_passkey( new PasskeyRecord( hash( 'sha256', 'cred' ), 'cred', 'PEM', 0, 'Key', 1, 0 ) );
	}

	/**
	 * @param array<string, bool> $flags Request flags.
	 */
	private function guard( array $flags ): PasswordAuthGuard {
		return new PasswordAuthGuard( new RequestContext( $flags ) );
	}

	public function test_xmlrpc_password_of_a_two_factor_user_is_refused(): void {
		$result = $this->guard( array( 'xmlrpc' => true ) )->filter( $this->alice, 'alice', 'pw' );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( PasswordAuthGuard::ERROR_CODE, $result->get_error_code() );
	}

	public function test_xmlrpc_password_without_two_factor_passes(): void {
		$this->assertSame( $this->bob, $this->guard( array( 'xmlrpc' => true ) )->filter( $this->bob, 'bob', 'pw' ) );
	}

	public function test_rest_and_ajax_passwords_are_refused_too(): void {
		$this->assertInstanceOf( \WP_Error::class, $this->guard( array( 'rest' => true ) )->filter( $this->alice, 'alice', 'pw' ) );
		$this->assertInstanceOf( \WP_Error::class, $this->guard( array( 'ajax' => true ) )->filter( $this->alice, 'alice', 'pw' ) );
	}

	public function test_interactive_login_is_left_to_the_interceptor(): void {
		$this->assertSame( $this->alice, $this->guard( array() )->filter( $this->alice, 'alice', 'pw' ) );
	}

	public function test_errors_and_nulls_pass_through(): void {
		$error = new \WP_Error( 'incorrect_password' );
		$guard = $this->guard( array( 'xmlrpc' => true ) );

		$this->assertSame( $error, $guard->filter( $error, 'alice', 'pw' ) );
		$this->assertNull( $guard->filter( null, 'alice', 'pw' ) );
	}

	public function test_an_application_password_of_the_same_user_passes(): void {
		$guard = $this->guard( array( 'xmlrpc' => true ) );
		$guard->note_app_password( $this->alice );

		$this->assertSame( $this->alice, $guard->filter( $this->alice, 'alice', 'xxxx xxxx' ) );
	}

	public function test_another_users_application_password_does_not_open_the_gate(): void {
		$guard = $this->guard( array( 'xmlrpc' => true ) );
		$guard->note_app_password( $this->bob );

		$this->assertInstanceOf( \WP_Error::class, $guard->filter( $this->alice, 'alice', 'pw' ) );
	}

	public function test_application_passwords_can_be_switched_off_for_two_factor_users(): void {
		$guard = $this->guard( array() );

		$this->assertFalse( $guard->filter_app_passwords( true, $this->alice ) );
		$this->assertTrue( $guard->filter_app_passwords( true, $this->bob ) );
		$this->assertFalse( $guard->filter_app_passwords( false, $this->bob ) );
	}

	public function test_register_wires_the_hooks(): void {
		$guard = $this->guard( array() );
		$guard->register( true );

		$this->assertSame( PasswordAuthGuard::PRIORITY, has_filter( 'authenticate', array( $guard, 'filter' ) ) );
		$this->assertNotFalse( has_action( 'application_password_did_authenticate', array( $guard, 'note_app_password' ) ) );
		$this->assertNotFalse( has_filter( 'wp_is_application_passwords_available_for_user', array( $guard, 'filter_app_passwords' ) ) );
	}

	public function test_app_password_filter_is_off_by_default(): void {
		$guard = $this->guard( array() );
		$guard->register( false );

		$this->assertFalse( has_filter( 'wp_is_application_passwords_available_for_user', array( $guard, 'filter_app_passwords' ) ) );
	}

	public function test_request_context_reads_flags(): void {
		$this->assertTrue( ( new RequestContext( array() ) )->is_interactive() );
		$this->assertFalse( ( new RequestContext( array( 'cron' => true ) ) )->is_interactive() );
		$this->assertFalse( ( new RequestContext( array( 'cli' => true ) ) )->is_interactive() );
		$this->assertFalse( ( new RequestContext( array( 'cli' => true ) ) )->refuses_passwords() );
		$this->assertTrue( ( new RequestContext( array( 'cron' => true ) ) )->refuses_passwords() );
	}

	public function test_request_context_detects_the_real_request(): void {
		Functions\when( 'wp_doing_ajax' )->justReturn( false );
		Functions\when( 'wp_doing_cron' )->justReturn( true );

		$this->assertFalse( ( new RequestContext() )->is_interactive() );
	}
}
