<?php
/**
 * Tests for Googlebot DNS verification.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\GooglebotVerifier;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\GooglebotVerifier
 */
final class GooglebotVerifierTest extends TestCase {

	private const UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

	/**
	 * Build a verifier over fixed DNS answers, counting reverse lookups.
	 *
	 * @param string             $host    Reverse answer.
	 * @param array<int, string> $forward Forward answer.
	 * @param int                $lookups Reverse lookup counter (by reference).
	 * @return GooglebotVerifier
	 */
	private function verifier( string $host, array $forward, int &$lookups = 0 ): GooglebotVerifier {
		return new GooglebotVerifier(
			new ArrayStorage(),
			static function () use ( $host, &$lookups ): string {
				++$lookups;
				return $host;
			},
			static fn (): array => $forward
		);
	}

	public function test_genuine_googlebot_is_verified(): void {
		$this->assertTrue( $this->verifier( 'crawl-66-249-66-1.googlebot.com', [ '66.249.66.1' ] )->is_verified( '66.249.66.1', self::UA ) );
	}

	public function test_foreign_reverse_domain_is_rejected(): void {
		$this->assertFalse( $this->verifier( 'googlebot.com.evil.example', [ '66.249.66.1' ] )->is_verified( '66.249.66.1', self::UA ) );
	}

	public function test_forward_mismatch_is_rejected(): void {
		$this->assertFalse( $this->verifier( 'crawl.googlebot.com', [ '203.0.113.9' ] )->is_verified( '66.249.66.1', self::UA ) );
	}

	public function test_non_googlebot_user_agent_skips_dns(): void {
		$lookups = 0;
		$this->verifier( 'crawl.googlebot.com', [ '66.249.66.1' ], $lookups )->is_verified( '66.249.66.1', 'Mozilla/5.0 Chrome/142' );

		$this->assertSame( 0, $lookups );
	}

	public function test_verdict_is_cached(): void {
		$lookups  = 0;
		$verifier = $this->verifier( 'crawl.googlebot.com', [ '66.249.66.1' ], $lookups );
		$verifier->is_verified( '66.249.66.1', self::UA );
		$verifier->is_verified( '66.249.66.1', self::UA );

		$this->assertSame( 1, $lookups );
	}

	public function test_ipv6_googlebot_is_verified(): void {
		$this->assertTrue( $this->verifier( 'crawl.googlebot.com', [ '2001:4860:4801:0010::1' ] )->is_verified( '2001:4860:4801:10::1', self::UA ) );
	}
}
