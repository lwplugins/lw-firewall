<?php
/**
 * Signed, time-bound registration token (proof-of-render).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Issues and verifies an HMAC token embedded in the registration form. A valid
 * token proves the form was actually rendered to a client, which a direct-POST
 * bot cannot fake. Timing and single-use checks defeat the render-and-replay
 * case.
 */
final class RegisterToken {

	/**
	 * Issue a token stamped with the current time.
	 *
	 * @return string
	 */
	public static function issue(): string {
		return self::make( time() );
	}

	/**
	 * Build a token for a given issue time (seam for deterministic tests).
	 *
	 * @param int $issued UNIX timestamp the token was issued.
	 * @return string
	 */
	public static function make( int $issued ): string {
		$issued_str = (string) $issued;
		$hmac       = hash_hmac( 'sha256', $issued_str, self::secret() );

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Benign: compact form-safe encoding of the signed token, not obfuscation.
		return base64_encode( $issued_str . ':' . $hmac );
	}

	/**
	 * Verify a token against the current time.
	 *
	 * @param string                $token    Raw token from the form.
	 * @param int                   $min_fill Minimum age in seconds (timing floor).
	 * @param int                   $max_age  Maximum age in seconds (expiry).
	 * @param StorageInterface|null $storage  When given, enforces single-use.
	 * @return bool
	 */
	public static function verify( string $token, int $min_fill, int $max_age, ?StorageInterface $storage = null ): bool {
		return self::check( $token, time(), $min_fill, $max_age, $storage );
	}

	/**
	 * Verify a token against an explicit "now" (seam for deterministic tests).
	 *
	 * @param string                $token    Raw token from the form.
	 * @param int                   $now      Current UNIX timestamp.
	 * @param int                   $min_fill Minimum age in seconds (timing floor).
	 * @param int                   $max_age  Maximum age in seconds (expiry).
	 * @param StorageInterface|null $storage  When given, enforces single-use.
	 * @return bool
	 */
	public static function check( string $token, int $now, int $min_fill, int $max_age, ?StorageInterface $storage = null ): bool {
		if ( '' === $token ) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Benign: decodes our own signed token, validated by HMAC below.
		$decoded = base64_decode( $token, true );

		if ( false === $decoded || ! str_contains( $decoded, ':' ) ) {
			return false;
		}

		[ $issued, $hmac ] = explode( ':', $decoded, 2 );

		if ( '' === $issued || ! ctype_digit( $issued ) ) {
			return false;
		}

		$expected = hash_hmac( 'sha256', $issued, self::secret() );

		if ( ! hash_equals( $expected, $hmac ) ) {
			return false;
		}

		$age = $now - (int) $issued;

		if ( $age < $min_fill || $age > $max_age ) {
			return false;
		}

		if ( null !== $storage ) {
			$key = 'reg_tok_' . hash( 'sha256', $decoded );

			if ( $storage->get( $key ) ) {
				return false;
			}

			$storage->set( $key, 1, $max_age );
		}

		return true;
	}

	/**
	 * Per-site secret used for the HMAC.
	 *
	 * @return string
	 */
	private static function secret(): string {
		return wp_salt( 'nonce' );
	}
}
