<?php
/**
 * Tests for the comment guard's hook callbacks (bypass rules and scope).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rules\CommentFields;
use LightweightPlugins\Firewall\Rules\CommentGuard;
use LightweightPlugins\Firewall\Rules\RegisterToken;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use WP_Error;

require_once dirname( __DIR__ ) . '/Support/WpError.php';

/**
 * Paths that would count toward a ban resolve the real storage backend, so
 * they are covered by CommentSpamCheckTest and the on-site verification;
 * these tests cover what decides whether the check runs at all.
 *
 * @covers \LightweightPlugins\Firewall\Rules\CommentGuard
 */
final class CommentGuardTest extends MonkeyTestCase {

	/**
	 * Superglobals before the test.
	 *
	 * @var array<string, array<string, mixed>>
	 */
	private array $globals = array();

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'DAY_IN_SECONDS' ) ) {
			define( 'DAY_IN_SECONDS', 86400 );
		}

		$this->globals = array(
			'post'   => $_POST,
			'server' => $_SERVER,
		);

		$_SERVER['REMOTE_ADDR'] = '8.8.8.8';
		$_POST                  = array();

		Functions\stubTranslationFunctions();
		Functions\stubEscapeFunctions();
		Functions\when( 'wp_salt' )->justReturn( 'unit-test-fixed-salt-value' );
		Functions\when( 'wp_unslash' )->returnArg();
		Functions\when( 'sanitize_text_field' )->alias( 'trim' );
		Functions\when( 'current_user_can' )->justReturn( false );

		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false ) ) );
	}

	protected function tearDown(): void {
		$_POST   = $this->globals['post'];
		$_SERVER = $this->globals['server'];
		parent::tearDown();
	}

	private static function submit( array $post ): mixed {
		$_POST = $post;
		CommentGuard::mark_submission( 7 );

		return CommentGuard::filter_approved( 0, array( 'comment_post_ID' => 7 ) );
	}

	/**
	 * REST, XML-RPC and admin replies never pass through the comment form,
	 * so they never render the token and must not be checked.
	 */
	public function test_a_comment_not_sent_through_the_form_is_not_checked(): void {
		$_POST = array( CommentFields::HONEYPOT_FIELD => 'filled' );

		$this->assertSame( 1, CommentGuard::filter_approved( 1, array( 'comment_post_ID' => 7 ) ) );
	}

	public function test_an_earlier_refusal_is_kept(): void {
		$error = new WP_Error( 'comment_flood', 'slow down' );
		CommentGuard::mark_submission( 7 );

		$this->assertSame( $error, CommentGuard::filter_approved( $error, array( 'comment_post_ID' => 7 ) ) );
	}

	public function test_a_rendered_form_is_accepted_with_its_status_unchanged(): void {
		$token = RegisterToken::make( time() - 30, 'comment', 'nonce' );

		$this->assertSame( 0, self::submit( array( CommentFields::TOKEN_FIELD => $token ) ) );
	}

	public function test_a_moderator_or_post_editor_is_never_checked(): void {
		Functions\when( 'current_user_can' )->justReturn( true );

		$this->assertSame( 0, self::submit( array( CommentFields::HONEYPOT_FIELD => 'filled' ) ) );
	}

	public function test_a_whitelisted_ip_is_never_checked(): void {
		OptionStore::install( array( 'lw_firewall' => array( 'ip_whitelist' => array( '8.8.8.8' ) ) ) );

		$this->assertSame( 0, self::submit( array() ) );
	}

	/**
	 * An expired token is refused but never counted, so this path touches no
	 * storage — and shows the refusal is a 403 that aborts the insert.
	 */
	public function test_a_stale_form_is_refused_with_a_403(): void {
		$token  = RegisterToken::make( time() - 2 * 86400, 'comment', 'nonce' );
		$result = self::submit( array( CommentFields::TOKEN_FIELD => $token ) );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( array( 'lw_fw_comment_spam', 403 ), array( $result->get_error_code(), $result->get_error_data() ) );
	}

	public function test_the_submission_mark_is_consumed_by_one_comment(): void {
		$token = RegisterToken::make( time() - 30, 'comment', 'nonce' );
		self::submit( array( CommentFields::TOKEN_FIELD => $token ) );
		$_POST = array();

		$this->assertSame( 1, CommentGuard::filter_approved( 1, array( 'comment_post_ID' => 7 ) ) );
	}
}
