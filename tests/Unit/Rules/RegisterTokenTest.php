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
	 * Regression: the signature covered only the timestamp, so every form
	 * rendered in the same second produced a byte-identical token. With
	 * single-use on, all but the first visitor was rejected, and a shared page
	 * cache handed one token to everybody. A per-render nonce makes them
	 * distinct.
	 */
	public function test_two_tokens_issued_in_the_same_second_differ(): void {
		$a = RegisterToken::make( self::NOW, 'reg', 'nonce-one' );
		$b = RegisterToken::make( self::NOW, 'reg', 'nonce-two' );

		$this->assertNotSame( $a, $b );
	}

	public function test_both_same_second_tokens_are_accepted_with_single_use(): void {
		$storage = new ArrayStorage();
		$a       = RegisterToken::make( self::NOW - self::MIN, 'reg', 'nonce-one' );
		$b       = RegisterToken::make( self::NOW - self::MIN, 'reg', 'nonce-two' );

		$this->assertTrue( RegisterToken::check( $a, self::NOW, self::MIN, self::MAX, $storage, 'reg' ) );
		$this->assertTrue( RegisterToken::check( $b, self::NOW, self::MIN, self::MAX, $storage, 'reg' ) );
	}

	/**
	 * The scope is inside the signature, so a token handed out by one form
	 * cannot be presented to another.
	 */
	public function test_a_token_is_bound_to_the_form_that_issued_it(): void {
		$token = RegisterToken::make( self::NOW - self::MIN, 'reg', 'nonce-one' );

		$this->assertTrue( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, null, 'reg' ) );
		$this->assertFalse( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, null, 'reset' ) );
	}

	public function test_single_use_still_blocks_a_replay_within_one_scope(): void {
		$storage = new ArrayStorage();
		$token   = RegisterToken::make( self::NOW - self::MIN, 'reset', 'nonce-one' );

		$this->assertTrue( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, $storage, 'reset' ) );
		$this->assertFalse( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, $storage, 'reset' ) );
	}

	public function test_a_tampered_payload_is_rejected(): void {
		$token   = RegisterToken::make( self::NOW - self::MIN, 'reg', 'nonce-one' );
		$decoded = base64_decode( $token, true );
		$forged  = base64_encode( str_replace( '.reg.', '.reset.', (string) $decoded ) );

		$this->assertFalse( RegisterToken::check( $forged, self::NOW, self::MIN, self::MAX, null, 'reset' ) );
	}

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
			public function delete( string $key ): bool {
				unset( $this->counts[ $key ] );
				return true; }
			public static function is_available(): bool {
				return true; }
		};

		$token = RegisterToken::make( self::NOW - 10 );

		$this->assertTrue( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, $storage ) );
		$this->assertFalse( RegisterToken::check( $token, self::NOW, self::MIN, self::MAX, $storage ) );
	}
}
