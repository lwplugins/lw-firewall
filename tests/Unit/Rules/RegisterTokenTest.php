<?php
/**
 * Characterization tests for the signed registration token.
 *
 * Converted from the original dependency-free tests/register-token-test.php.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rules\RegisterToken;
use LightweightPlugins\Firewall\Storage\StorageInterface;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;

/**
 * @covers \LightweightPlugins\Firewall\Rules\RegisterToken
 */
final class RegisterTokenTest extends MonkeyTestCase {

	private const NOW = 1000000;
	private const MIN = 2;
	private const MAX = 3600;

	protected function setUp(): void {
		parent::setUp();
		Functions\when( 'wp_salt' )->justReturn( 'unit-test-fixed-salt-value' );
	}

	public function test_valid_fresh_token_passes(): void {
		$token = RegisterToken::make( self::NOW - 10 );

		$this->assertTrue( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX ) );
	}

	public function test_empty_token_rejected(): void {
		$this->assertFalse( RegisterToken::check( '', self::NOW, self::MIN, self::MAX ) );
	}

	public function test_tampered_hmac_rejected(): void {
		$tampered = base64_encode( ( self::NOW - 10 ) . ':deadbeef' );

		$this->assertFalse( RegisterToken::check( $tampered, self::NOW, self::MIN, self::MAX ) );
	}

	public function test_expired_token_rejected(): void {
		$token = RegisterToken::make( self::NOW - ( self::MAX + 1 ) );

		$this->assertFalse( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX ) );
	}

	public function test_too_fast_token_rejected(): void {
		$token = RegisterToken::make( self::NOW );

		$this->assertFalse( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX ) );
	}

	public function test_single_use_first_pass_then_replay_rejected(): void {
		$storage = new ArrayStorage();
		$token   = RegisterToken::make( self::NOW - 10 );

		$this->assertTrue( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, $storage ) );
		$this->assertFalse( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, $storage ) );
	}

	/**
	 * Single-use must rely on the atomic increment(), not a get()-then-set().
	 * This storage double never reports the key as seen via get() (simulating
	 * two concurrent requests in the TOCTOU window), but counts via increment().
	 * A get-then-set implementation would pass the token twice; the atomic one
	 * rejects the second use.
	 */
	public function test_single_use_is_race_safe(): void {
		$storage = new class() implements StorageInterface {
			/** @var array<string, int> */
			private array $counts = array();
			public function get( string $key ): mixed {
				return null; }
			public function set( string $key, mixed $value, int $ttl ): bool {
				return true; }
			public function increment( string $key, int $ttl ): int {
				$this->counts[ $key ] = ( $this->counts[ $key ] ?? 0 ) + 1;
				return $this->counts[ $key ]; }
			public static function is_available(): bool {
				return true; }
		};

		$token = RegisterToken::make( self::NOW - 10 );

		$this->assertTrue( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, $storage ) );
		$this->assertFalse( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, $storage ) );
	}
}
