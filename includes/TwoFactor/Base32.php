<?php
/**
 * RFC 4648 Base32 codec (no padding on output).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base32 encoder/decoder used for TOTP secrets.
 */
final class Base32 {

	private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Encode raw bytes to Base32 without padding.
	 *
	 * @param string $bytes Raw bytes.
	 * @return string
	 */
	public static function encode( string $bytes ): string {
		$out    = '';
		$buffer = 0;
		$bits   = 0;
		$len    = strlen( $bytes );

		for ( $i = 0; $i < $len; $i++ ) {
			$buffer = ( $buffer << 8 ) | ord( $bytes[ $i ] );
			$bits  += 8;
			while ( $bits >= 5 ) {
				$bits -= 5;
				$out  .= self::ALPHABET[ ( $buffer >> $bits ) & 31 ];
			}
			$buffer &= ( 1 << $bits ) - 1;
		}
		if ( $bits > 0 ) {
			$out .= self::ALPHABET[ ( $buffer << ( 5 - $bits ) ) & 31 ];
		}

		return $out;
	}

	/**
	 * Decode Base32 text. Case, whitespace and trailing "=" padding are ignored.
	 *
	 * Returns an empty string when the text contains any character outside
	 * the alphabet (never throws, never warns).
	 *
	 * @param string $text Base32 text.
	 * @return string Raw bytes, or '' on invalid input.
	 */
	public static function decode( string $text ): string {
		$text = strtoupper( (string) preg_replace( '/\s+/', '', $text ) );
		$text = rtrim( $text, '=' );

		if ( '' === $text || 1 !== preg_match( '/^[A-Z2-7]+$/', $text ) ) {
			return '';
		}

		$out    = '';
		$buffer = 0;
		$bits   = 0;
		$len    = strlen( $text );

		for ( $i = 0; $i < $len; $i++ ) {
			$buffer = ( $buffer << 5 ) | (int) strpos( self::ALPHABET, $text[ $i ] );
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits -= 8;
				$out  .= chr( ( $buffer >> $bits ) & 255 );
			}
			$buffer &= ( 1 << $bits ) - 1;
		}

		return $out;
	}
}
