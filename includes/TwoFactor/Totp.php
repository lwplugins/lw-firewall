<?php
/**
 * TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30 second step).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pure TOTP logic: secret generation, code calculation and verification.
 */
final class Totp {

	public const PERIOD = 30;
	public const DIGITS = 6;

	/**
	 * Generate a new secret: 20 random bytes as 32 Base32 characters.
	 *
	 * @return string
	 */
	public static function generate_secret(): string {
		return Base32::encode( random_bytes( 20 ) );
	}

	/**
	 * Code for a given time step.
	 *
	 * @param string $secret_b32 Base32 secret.
	 * @param int    $step       Time step (unix time / 30).
	 * @return string Six digits, zero padded. Empty string if the secret cannot be decoded.
	 */
	public static function code_at( string $secret_b32, int $step ): string {
		$key = Base32::decode( $secret_b32 );
		if ( '' === $key ) {
			return '';
		}

		$hash   = hash_hmac( 'sha1', pack( 'J', $step ), $key, true );
		$offset = ord( $hash[19] ) & 0x0f;
		$value  = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
			| ( ord( $hash[ $offset + 1 ] ) << 16 )
			| ( ord( $hash[ $offset + 2 ] ) << 8 )
			| ord( $hash[ $offset + 3 ] );

		return str_pad( (string) ( $value % 1000000 ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a code within a +/-1 step window, refusing replays.
	 *
	 * @param string $secret_b32 Base32 secret.
	 * @param string $code       User input (spaces are stripped).
	 * @param int    $last_step  Last accepted step; only steps above it are accepted.
	 * @param int    $now        Current unix time (injected).
	 * @return int|null Accepted step, or null.
	 */
	public static function verify( string $secret_b32, string $code, int $last_step, int $now ): ?int {
		$code = str_replace( ' ', '', $code );
		if ( 1 !== preg_match( '/^[0-9]{6}$/', $code ) ) {
			return null;
		}

		$current  = intdiv( $now, self::PERIOD );
		$accepted = null;

		for ( $step = $current - 1; $step <= $current + 1; $step++ ) {
			$expected = self::code_at( $secret_b32, $step );
			if ( '' === $expected ) {
				return null;
			}
			if ( hash_equals( $expected, $code ) && $step > $last_step && null === $accepted ) {
				$accepted = $step;
			}
		}

		return $accepted;
	}

	/**
	 * Build the otpauth provisioning URI for authenticator apps.
	 *
	 * @param string $secret_b32 Base32 secret.
	 * @param string $account    Account label (e.g. email).
	 * @param string $issuer     Issuer (e.g. site name).
	 * @return string
	 */
	public static function provisioning_uri( string $secret_b32, string $account, string $issuer ): string {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );

		return 'otpauth://totp/' . $label
			. '?secret=' . rawurlencode( $secret_b32 )
			. '&issuer=' . rawurlencode( $issuer )
			. '&algorithm=SHA1&digits=6&period=30';
	}

	/**
	 * Provisioning URI with this site's name as the issuer.
	 *
	 * @param string $secret_b32 Base32 secret.
	 * @param string $account    Account label (the user login).
	 * @return string
	 */
	public static function site_uri( string $secret_b32, string $account ): string {
		$issuer = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );

		return self::provisioning_uri( $secret_b32, $account, '' !== $issuer ? $issuer : 'WordPress' );
	}
}
