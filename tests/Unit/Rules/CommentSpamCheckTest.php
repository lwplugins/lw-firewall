<?php
/**
 * Tests for the comment/review spam verdict.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rules\CommentSpamCheck;
use LightweightPlugins\Firewall\Rules\RegisterToken;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\CommentSpamCheck
 */
final class CommentSpamCheckTest extends MonkeyTestCase {

	private const NOW = 2000000;

	private const POLICY = array(
		'honeypot' => true,
		'token'    => true,
		'min_fill' => 2,
		'max_age'  => 86400,
	);

	protected function setUp(): void {
		parent::setUp();
		Functions\when( 'wp_salt' )->justReturn( 'unit-test-fixed-salt-value' );
	}

	private static function token( int $age, string $scope = 'comment' ): string {
		return RegisterToken::make( self::NOW - $age, $scope, 'nonce' );
	}

	public function test_a_rendered_form_submitted_normally_passes(): void {
		$this->assertSame( CommentSpamCheck::OK, CommentSpamCheck::evaluate( '', self::token( 30 ), self::POLICY, self::NOW ) );
	}

	/**
	 * Tokens are described, not built, in the provider: providers run before
	 * setUp(), so the HMAC salt stub is not in place yet.
	 *
	 * @dataProvider provide_rejections
	 *
	 * @param string          $honeypot Submitted honeypot.
	 * @param array{0: string, 1?: int, 2?: string} $token Token spec: kind, age, scope.
	 * @param string          $expected Verdict.
	 */
	public function test_bot_submissions_are_rejected( string $honeypot, array $token, string $expected ): void {
		$raw = match ( $token[0] ) {
			'none'   => '',
			'forged' => base64_encode( 'v2.1.comment.x:deadbeef' ),
			default  => self::token( $token[1] ?? 30, $token[2] ?? 'comment' ),
		};

		$this->assertSame( $expected, CommentSpamCheck::evaluate( $honeypot, $raw, self::POLICY, self::NOW ) );
	}

	/**
	 * @return array<string, array{0: string, 1: array<int, int|string>, 2: string}>
	 */
	public static function provide_rejections(): array {
		return array(
			'honeypot filled'           => array( 'https://spam.example', array( 'signed', 30 ), CommentSpamCheck::HONEYPOT ),
			'direct POST without token' => array( '', array( 'none' ), CommentSpamCheck::NO_TOKEN ),
			'forged token'              => array( '', array( 'forged' ), CommentSpamCheck::BAD_TOKEN ),
			'registration token reused' => array( '', array( 'signed', 30, 'reg' ), CommentSpamCheck::BAD_TOKEN ),
			'posted instantly'          => array( '', array( 'signed', 0 ), CommentSpamCheck::TOO_FAST ),
			'token older than lifetime' => array( '', array( 'signed', 86401 ), CommentSpamCheck::EXPIRED ),
		);
	}

	/**
	 * The honeypot field may be missing (a hand-built theme form never
	 * renders it); only a filled one is evidence.
	 *
	 * @dataProvider provide_empty_honeypots
	 */
	public function test_an_empty_or_missing_honeypot_is_not_evidence( string $honeypot ): void {
		$this->assertSame( CommentSpamCheck::OK, CommentSpamCheck::evaluate( $honeypot, self::token( 30 ), self::POLICY, self::NOW ) );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_empty_honeypots(): array {
		return array(
			'missing'    => array( '' ),
			'whitespace' => array( '   ' ),
		);
	}

	public function test_honeypot_only_mode_accepts_a_submission_without_token(): void {
		$policy = array_merge( self::POLICY, array( 'token' => false ) );

		$this->assertSame( CommentSpamCheck::OK, CommentSpamCheck::evaluate( '', '', $policy, self::NOW ) );
	}

	public function test_a_filled_honeypot_is_ignored_when_the_honeypot_is_off(): void {
		$policy = array_merge( self::POLICY, array( 'honeypot' => false ) );

		$this->assertSame( CommentSpamCheck::OK, CommentSpamCheck::evaluate( 'filled', self::token( 30 ), $policy, self::NOW ) );
	}

	/**
	 * Full-page caching: a page cached for hours still carries a valid token
	 * as long as it is within the lifetime.
	 */
	public function test_a_token_from_a_page_cached_for_hours_passes(): void {
		$this->assertSame( CommentSpamCheck::OK, CommentSpamCheck::evaluate( '', self::token( 20 * 3600 ), self::POLICY, self::NOW ) );
	}

	/**
	 * @dataProvider provide_ban_evidence
	 */
	public function test_only_bot_evidence_counts_toward_a_ban( string $verdict, bool $expected ): void {
		$this->assertSame( $expected, CommentSpamCheck::counts_toward_ban( $verdict ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function provide_ban_evidence(): array {
		return array(
			'passed'    => array( CommentSpamCheck::OK, false ),
			'expired'   => array( CommentSpamCheck::EXPIRED, false ),
			'honeypot'  => array( CommentSpamCheck::HONEYPOT, true ),
			'no token'  => array( CommentSpamCheck::NO_TOKEN, true ),
			'bad token' => array( CommentSpamCheck::BAD_TOKEN, true ),
			'too fast'  => array( CommentSpamCheck::TOO_FAST, true ),
		);
	}

	/**
	 * @dataProvider provide_exemptions
	 *
	 * @param bool               $cli        WP-CLI.
	 * @param bool               $privileged Moderator or post editor.
	 * @param array<int, string> $whitelist  Whitelist.
	 * @param bool               $expected   Exempt.
	 */
	public function test_exemptions( bool $cli, bool $privileged, array $whitelist, bool $expected ): void {
		$this->assertSame( $expected, CommentSpamCheck::is_exempt( $cli, $privileged, '8.8.8.8', $whitelist ) );
	}

	/**
	 * @return array<string, array{0: bool, 1: bool, 2: array<int, string>, 3: bool}>
	 */
	public static function provide_exemptions(): array {
		return array(
			'anonymous visitor'       => array( false, false, array(), false ),
			'other whitelist entries' => array( false, false, array( '1.1.1.1' ), false ),
			'moderator or editor'     => array( false, true, array(), true ),
			'whitelisted IP'          => array( false, false, array( '8.8.8.0/24' ), true ),
			'WP-CLI'                  => array( true, false, array(), true ),
		);
	}
}
