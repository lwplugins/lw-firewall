<?php
/**
 * Tests for recovery codes.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\RecoveryCodes;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\RecoveryCodes
 */
final class RecoveryCodesTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\when( 'wp_hash_password' )->alias(
			static fn( string $p ): string => password_hash( $p, PASSWORD_DEFAULT )
		);
		Functions\when( 'wp_check_password' )->alias(
			static fn( string $p, string $h ): bool => password_verify( $p, $h )
		);
	}

	public function test_generates_ten_unique_formatted_codes(): void {
		$set = RecoveryCodes::generate();
		$this->assertCount( 10, $set['plain'] );
		$this->assertCount( 10, $set['hashes'] );
		$this->assertCount( 10, array_unique( $set['plain'] ) );
		foreach ( $set['plain'] as $code ) {
			$this->assertMatchesRegularExpression( '/^[2-9a-hj-km-np-z]{4}-[2-9a-hj-km-np-z]{4}$/', $code );
		}
	}

	public function test_consume_works_once(): void {
		$set       = RecoveryCodes::generate( 3 );
		$remaining = RecoveryCodes::consume( $set['plain'][1], $set['hashes'] );
		$this->assertIsArray( $remaining );
		$this->assertCount( 2, $remaining );
		$this->assertSame( array( 0, 1 ), array_keys( $remaining ) );
		$this->assertNull( RecoveryCodes::consume( $set['plain'][1], $remaining ) );
		$this->assertIsArray( RecoveryCodes::consume( $set['plain'][0], $remaining ) );
	}

	public function test_normalizes_input(): void {
		Functions\when( 'wp_hash_password' )->alias(
			static fn( string $p ): string => password_hash( $p, PASSWORD_DEFAULT )
		);
		$hashes = array( password_hash( 'abcdefgh', PASSWORD_DEFAULT ) );
		$this->assertSame( array(), RecoveryCodes::consume( 'ABCD EFGH', $hashes ) );
		$this->assertSame( array(), RecoveryCodes::consume( ' abcd-efgh ', $hashes ) );
	}

	public function test_wrong_code_returns_null(): void {
		$set = RecoveryCodes::generate( 2 );
		$this->assertNull( RecoveryCodes::consume( 'zzzz-zzzz', $set['hashes'] ) );
		$this->assertNull( RecoveryCodes::consume( '', $set['hashes'] ) );
	}
}
