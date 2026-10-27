<?php
/**
 * Tests for the Base32 codec.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\Base32;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\Base32
 */
final class Base32Test extends MonkeyTestCase {

	public function test_rfc4648_vectors(): void {
		$this->assertSame( '', Base32::encode( '' ) );
		$this->assertSame( 'MY', Base32::encode( 'f' ) );
		$this->assertSame( 'MZXQ', Base32::encode( 'fo' ) );
		$this->assertSame( 'MZXW6', Base32::encode( 'foo' ) );
		$this->assertSame( 'MZXW6YQ', Base32::encode( 'foob' ) );
		$this->assertSame( 'MZXW6YTB', Base32::encode( 'fooba' ) );
		$this->assertSame( 'MZXW6YTBOI', Base32::encode( 'foobar' ) );
	}

	public function test_round_trip_for_zero_to_twentyfive_bytes(): void {
		for ( $len = 0; $len <= 25; $len++ ) {
			$bytes = '';
			for ( $i = 0; $i < $len; $i++ ) {
				$bytes .= chr( ( $i * 37 + $len * 11 ) % 256 );
			}
			$this->assertSame( $bytes, Base32::decode( Base32::encode( $bytes ) ), "length $len" );
		}
	}

	public function test_decode_tolerates_case_spaces_and_padding(): void {
		$this->assertSame( 'foobar', Base32::decode( 'mzxw 6ytb oi' ) );
		$this->assertSame( 'foobar', Base32::decode( "MZXW6YTBOI======\n" ) );
		$this->assertSame( 'f', Base32::decode( 'my======' ) );
	}

	public function test_decode_returns_empty_string_on_invalid_characters(): void {
		$this->assertSame( '', Base32::decode( 'MZXW6!' ) );
		$this->assertSame( '', Base32::decode( 'MZXW1' ) );
		$this->assertSame( '', Base32::decode( 'MZ=XW6' ) );
	}
}
