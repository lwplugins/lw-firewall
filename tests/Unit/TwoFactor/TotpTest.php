<?php
/**
 * Tests for TOTP (RFC 6238, SHA1, 6 digits, 30 s).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\Base32;
use LightweightPlugins\Firewall\TwoFactor\Totp;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\Totp
 */
final class TotpTest extends MonkeyTestCase {

	private function secret(): string {
		return Base32::encode( '12345678901234567890' );
	}

	/**
	 * @return array<string, array{int, string}>
	 */
	public static function rfc_vectors(): array {
		return array(
			'T=59'         => array( 59, '287082' ),
			'T=1111111109' => array( 1111111109, '081804' ),
			'T=1234567890' => array( 1234567890, '005924' ),
			'T=2000000000' => array( 2000000000, '279037' ),
		);
	}

	/**
	 * @dataProvider rfc_vectors
	 */
	public function test_code_at_matches_rfc_6238( int $time, string $expected ): void {
		$this->assertSame( $expected, Totp::code_at( $this->secret(), intdiv( $time, 30 ) ) );
	}

	public function test_generate_secret_is_32_base32_chars_of_20_bytes(): void {
		$secret = Totp::generate_secret();
		$this->assertMatchesRegularExpression( '/^[A-Z2-7]{32}$/', $secret );
		$this->assertSame( 20, strlen( Base32::decode( $secret ) ) );
		$this->assertNotSame( $secret, Totp::generate_secret() );
	}

	public function test_verify_accepts_exact_and_adjacent_steps(): void {
		$now  = 1234567890;
		$step = intdiv( $now, 30 );
		$this->assertSame( $step, Totp::verify( $this->secret(), '005924', 0, $now ) );
		$this->assertSame( $step - 1, Totp::verify( $this->secret(), Totp::code_at( $this->secret(), $step - 1 ), 0, $now ) );
		$this->assertSame( $step + 1, Totp::verify( $this->secret(), Totp::code_at( $this->secret(), $step + 1 ), 0, $now ) );
	}

	public function test_verify_rejects_two_steps_away(): void {
		$now  = 1234567890;
		$step = intdiv( $now, 30 );
		$this->assertNull( Totp::verify( $this->secret(), Totp::code_at( $this->secret(), $step - 2 ), 0, $now ) );
		$this->assertNull( Totp::verify( $this->secret(), Totp::code_at( $this->secret(), $step + 2 ), 0, $now ) );
	}

	public function test_verify_rejects_replay_of_last_step(): void {
		$now  = 1234567890;
		$step = intdiv( $now, 30 );
		$this->assertNull( Totp::verify( $this->secret(), '005924', $step, $now ) );
		$this->assertNull( Totp::verify( $this->secret(), '005924', $step + 5, $now ) );
	}

	public function test_verify_strips_spaces(): void {
		$this->assertSame( intdiv( 1234567890, 30 ), Totp::verify( $this->secret(), '005 924', 0, 1234567890 ) );
	}

	public function test_verify_rejects_malformed_codes(): void {
		$now = 1234567890;
		foreach ( array( '', '5924', '0059240', '+05924', '-05924', '00592a', '0x5924', '００５９２４' ) as $bad ) {
			$this->assertNull( Totp::verify( $this->secret(), $bad, 0, $now ), "code '$bad'" );
		}
	}

	public function test_verify_returns_null_for_undecodable_secret(): void {
		$this->assertNull( Totp::verify( 'not*base32!', '005924', 0, 1234567890 ) );
		$this->assertNull( Totp::verify( '', '005924', 0, 1234567890 ) );
	}

	public function test_provisioning_uri_is_url_encoded(): void {
		$uri = Totp::provisioning_uri( 'ABCDEF', 'józsi@example.com', 'Példa Oldal & Co' );
		$this->assertSame(
			'otpauth://totp/P%C3%A9lda%20Oldal%20%26%20Co:j%C3%B3zsi%40example.com'
			. '?secret=ABCDEF&issuer=P%C3%A9lda%20Oldal%20%26%20Co&algorithm=SHA1&digits=6&period=30',
			$uri
		);
	}
}
