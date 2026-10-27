<?php
/**
 * Tests for the strict base64url codec.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey;

use LightweightPlugins\Firewall\TwoFactor\Passkey\Base64Url;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\Passkey\Base64Url
 */
final class Base64UrlTest extends TestCase {

	public function test_round_trip_without_padding(): void {
		for ( $len = 0; $len < 40; $len++ ) {
			$bin = $len > 0 ? random_bytes( $len ) : '';
			$enc = Base64Url::encode( $bin );
			$this->assertDoesNotMatchRegularExpression( '/[+\/=]/', $enc );
			$this->assertSame( $bin, Base64Url::decode( $enc ) );
		}
	}

	public function test_rejects_non_canonical_and_foreign_alphabet(): void {
		$this->assertNull( Base64Url::decode( 'ab+c' ) );
		$this->assertNull( Base64Url::decode( 'ab/c' ) );
		$this->assertNull( Base64Url::decode( 'YQ==' ) );
		$this->assertNull( Base64Url::decode( 'a' ) );
		$this->assertNull( Base64Url::decode( 'YR' ) ); // Non-zero trailing bits: not the canonical encoding of "a".
		$this->assertNull( Base64Url::decode( "YQ\n" ) );
		$this->assertSame( 'a', Base64Url::decode( 'YQ' ) );
		$this->assertSame( '', Base64Url::decode( '' ) );
	}
}
