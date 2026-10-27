<?php
/**
 * One-time recovery codes.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generates recovery codes (xxxx-xxxx) and consumes them against stored hashes.
 */
final class RecoveryCodes {

	private const ALPHABET = '23456789abcdefghjkmnpqrstuvwxyz';

	/**
	 * Generate fresh codes.
	 *
	 * @param int $count Number of codes.
	 * @return array{plain: string[], hashes: string[]}
	 */
	public static function generate( int $count = 10 ): array {
		$plain  = array();
		$hashes = array();
		while ( $count > 0 ) {
			$code = self::random_code();
			if ( in_array( $code, $plain, true ) ) {
				continue;
			}
			$plain[]  = $code;
			$hashes[] = wp_hash_password( self::normalize( $code ) );
			--$count;
		}

		return array(
			'plain'  => $plain,
			'hashes' => $hashes,
		);
	}

	/**
	 * Check a code and remove its hash.
	 *
	 * @param string   $input  Code as typed by the user.
	 * @param string[] $hashes Stored hashes.
	 * @return string[]|null Remaining hashes (re-indexed) on a match, null otherwise.
	 */
	public static function consume( string $input, array $hashes ): ?array {
		$normalized = self::normalize( $input );
		if ( '' === $normalized ) {
			return null;
		}

		$matched = null;
		foreach ( $hashes as $index => $hash ) {
			if ( null === $matched && wp_check_password( $normalized, (string) $hash ) ) {
				$matched = $index;
			}
		}
		if ( null === $matched ) {
			return null;
		}

		unset( $hashes[ $matched ] );

		return array_values( $hashes );
	}

	/**
	 * Lowercase, without dashes and whitespace.
	 *
	 * @param string $code Code.
	 * @return string
	 */
	private static function normalize( string $code ): string {
		return strtolower( (string) preg_replace( '/[\s-]+/', '', $code ) );
	}

	/**
	 * One random code in xxxx-xxxx form.
	 *
	 * @return string
	 */
	private static function random_code(): string {
		$max   = strlen( self::ALPHABET ) - 1;
		$chars = '';
		for ( $i = 0; $i < 8; $i++ ) {
			$chars .= self::ALPHABET[ random_int( 0, $max ) ];
		}

		return substr( $chars, 0, 4 ) . '-' . substr( $chars, 4 );
	}
}
