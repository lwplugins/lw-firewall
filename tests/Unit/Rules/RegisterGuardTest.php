<?php
/**
 * Tests for the registration guard's filter callback.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\IpSubject;
use LightweightPlugins\Firewall\Rules\RegisterGuard;
use LightweightPlugins\Firewall\Rules\RegisterToken;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use WP_Error;

require_once dirname( __DIR__ ) . '/Support/WpError.php';

/**
 * @covers \LightweightPlugins\Firewall\Rules\RegisterGuard
 */
final class RegisterGuardTest extends MonkeyTestCase {

	private const IP = '8.8.8.8';

	/**
	 * Superglobals before the test.
	 *
	 * @var array<string, array<string, mixed>>
	 */
	private array $globals = array();

	private ArrayStorage $storage;

	private OptionStore $options;

	protected function setUp(): void {
		parent::setUp();

		$this->globals = array(
			'post'   => $_POST,
			'server' => $_SERVER,
		);

		$_SERVER['REMOTE_ADDR'] = self::IP;
		$_POST                  = array();

		Functions\stubTranslationFunctions();
		Functions\when( 'wp_salt' )->justReturn( 'unit-test-fixed-salt-value' );
		Functions\when( 'wp_unslash' )->returnArg();
		Functions\when( 'sanitize_text_field' )->alias( 'trim' );

		$this->options = OptionStore::install(
			array(
				'lw_firewall' => array(
					'log_enabled'         => false,
					'register_single_use' => true,
				),
			)
		);
		$this->storage = new ArrayStorage();
		RegisterGuard::reset( $this->storage );
	}

	protected function tearDown(): void {
		RegisterGuard::reset();
		$_POST   = $this->globals['post'];
		$_SERVER = $this->globals['server'];
		parent::tearDown();
	}

	private static function post_form( string $token, string $honeypot = '' ): void {
		$_POST = array(
			'lw_fw_reg_token' => $token,
			'lw_fw_url'       => $honeypot,
		);
	}

	private static function fresh_token(): string {
		return RegisterToken::make( time() - 10, 'reg', bin2hex( random_bytes( 4 ) ) );
	}

	private function reject_count(): int {
		return (int) $this->storage->get( 'register_reject_' . IpSubject::of( self::IP ) );
	}

	/**
	 * @return array<int, string>
	 */
	private static function codes( mixed $errors ): array {
		return $errors->get_error_codes();
	}

	/**
	 * Regression (lehetekjol.hu, LearnDash 5.2.0): LearnDash applies
	 * registration_errors itself on register_post, then core applies it
	 * again. The first run spent the single-use token, the second saw a
	 * replay and refused — and counted — every genuine registration.
	 */
	public function test_registration_errors_applied_twice_in_one_request_is_not_spam(): void {
		self::post_form( self::fresh_token() );

		$this->assertSame( array(), self::codes( RegisterGuard::validate( new WP_Error() ) ) );
		$this->assertSame( array(), self::codes( RegisterGuard::validate( new WP_Error() ) ) );
		$this->assertSame( 0, $this->reject_count() );
	}

	/**
	 * Another plugin refused the form (terms box, password confirmation): the
	 * token was not spent, so resending the same page registers normally.
	 */
	public function test_a_form_refused_by_another_plugin_can_be_resent_with_the_same_token(): void {
		self::post_form( self::fresh_token() );

		$refused = RegisterGuard::validate( new WP_Error( 'terms', 'Accept the terms' ) );
		$this->assertSame( array( 'terms' ), self::codes( $refused ) );

		RegisterGuard::reset( $this->storage );

		$this->assertSame( array(), self::codes( RegisterGuard::validate( new WP_Error() ) ) );
		$this->assertSame( 0, $this->reject_count() );
	}

	public function test_a_spent_token_is_refused_without_counting_toward_a_ban(): void {
		self::post_form( self::fresh_token() );
		RegisterGuard::validate( new WP_Error() );

		RegisterGuard::reset( $this->storage );

		$this->assertSame( array( 'lw_fw_spam' ), self::codes( RegisterGuard::validate( new WP_Error() ) ) );
		$this->assertSame( 0, $this->reject_count() );
	}

	public function test_without_single_use_a_token_is_never_spent(): void {
		$this->options->data['lw_firewall']['register_single_use'] = false;
		self::post_form( self::fresh_token() );

		RegisterGuard::validate( new WP_Error() );
		RegisterGuard::reset( $this->storage );

		$this->assertSame( array(), self::codes( RegisterGuard::validate( new WP_Error() ) ) );
	}

	public function test_a_missing_token_is_refused_and_counted_once_per_request(): void {
		self::post_form( '' );

		$this->assertSame( array( 'lw_fw_spam' ), self::codes( RegisterGuard::validate( new WP_Error() ) ) );
		$this->assertSame( array( 'lw_fw_spam' ), self::codes( RegisterGuard::validate( new WP_Error() ) ) );
		$this->assertSame( 1, $this->reject_count() );
	}

	public function test_a_filled_honeypot_counts(): void {
		self::post_form( self::fresh_token(), 'http://spam.example' );

		$this->assertSame( array( 'lw_fw_spam' ), self::codes( RegisterGuard::validate( new WP_Error() ) ) );
		$this->assertSame( 1, $this->reject_count() );
	}

	public function test_an_expired_token_is_refused_without_counting(): void {
		self::post_form( RegisterToken::make( time() - 7200, 'reg', 'n' ) );

		$this->assertSame( array( 'lw_fw_spam' ), self::codes( RegisterGuard::validate( new WP_Error() ) ) );
		$this->assertSame( 0, $this->reject_count() );
	}

	public function test_a_non_error_input_is_passed_through(): void {
		$this->assertSame( 'odd', RegisterGuard::validate( 'odd' ) );
	}
}
