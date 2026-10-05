<?php
/**
 * Tests for the registration spam verdict.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rules\RegisterSpamCheck;
use LightweightPlugins\Firewall\Rules\RegisterToken;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\RegisterSpamCheck
 */
final class RegisterSpamCheckTest extends MonkeyTestCase {

	private const NOW = 1000000;

	private const POLICY = array(
		'honeypot' => true,
		'min_fill' => 2,
		'max_age'  => 3600,
	);

	protected function setUp(): void {
		parent::setUp();
		Functions\when( 'wp_salt' )->justReturn( 'unit-test-fixed-salt-value' );
	}

	public function test_a_fresh_token_passes(): void {
		$token = RegisterToken::make( self::NOW - 10, 'reg', 'n' );

		$this->assertSame( RegisterSpamCheck::OK, RegisterSpamCheck::evaluate( '', $token, self::POLICY, self::NOW ) );
	}

	public function test_a_filled_honeypot_wins(): void {
		$token = RegisterToken::make( self::NOW - 10, 'reg', 'n' );

		$this->assertSame( RegisterSpamCheck::HONEYPOT, RegisterSpamCheck::evaluate( 'x', $token, self::POLICY, self::NOW ) );
	}

	public function test_the_honeypot_is_ignored_when_off(): void {
		$token  = RegisterToken::make( self::NOW - 10, 'reg', 'n' );
		$policy = array_merge( self::POLICY, array( 'honeypot' => false ) );

		$this->assertSame( RegisterSpamCheck::OK, RegisterSpamCheck::evaluate( 'x', $token, $policy, self::NOW ) );
	}

	public function test_a_missing_token(): void {
		$this->assertSame( RegisterSpamCheck::NO_TOKEN, RegisterSpamCheck::evaluate( '', '', self::POLICY, self::NOW ) );
	}

	public function test_a_forged_token(): void {
		$this->assertSame( RegisterSpamCheck::BAD_TOKEN, RegisterSpamCheck::evaluate( '', 'Zm9vOmJhcg==', self::POLICY, self::NOW ) );
	}

	public function test_a_token_from_another_form_is_bad(): void {
		$token = RegisterToken::make( self::NOW - 10, 'comment', 'n' );

		$this->assertSame( RegisterSpamCheck::BAD_TOKEN, RegisterSpamCheck::evaluate( '', $token, self::POLICY, self::NOW ) );
	}

	public function test_an_expired_token(): void {
		$token = RegisterToken::make( self::NOW - 3601, 'reg', 'n' );

		$this->assertSame( RegisterSpamCheck::EXPIRED, RegisterSpamCheck::evaluate( '', $token, self::POLICY, self::NOW ) );
	}

	public function test_a_token_submitted_too_fast(): void {
		$token = RegisterToken::make( self::NOW - 1, 'reg', 'n' );

		$this->assertSame( RegisterSpamCheck::TOO_FAST, RegisterSpamCheck::evaluate( '', $token, self::POLICY, self::NOW ) );
	}

	/**
	 * Only bot evidence bans: a stale cached page, a token already spent by
	 * an earlier submission or a quick autofill is refused, never banned.
	 */
	public function test_only_bot_evidence_counts_toward_a_ban(): void {
		$this->assertTrue( RegisterSpamCheck::counts_toward_ban( RegisterSpamCheck::HONEYPOT ) );
		$this->assertTrue( RegisterSpamCheck::counts_toward_ban( RegisterSpamCheck::NO_TOKEN ) );
		$this->assertTrue( RegisterSpamCheck::counts_toward_ban( RegisterSpamCheck::BAD_TOKEN ) );
		$this->assertFalse( RegisterSpamCheck::counts_toward_ban( RegisterSpamCheck::OK ) );
		$this->assertFalse( RegisterSpamCheck::counts_toward_ban( RegisterSpamCheck::EXPIRED ) );
		$this->assertFalse( RegisterSpamCheck::counts_toward_ban( RegisterSpamCheck::REPLAYED ) );
		$this->assertFalse( RegisterSpamCheck::counts_toward_ban( RegisterSpamCheck::TOO_FAST ) );
	}
}
