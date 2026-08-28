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
	 * Token format version, signed along with the payload so a future change
	 * cannot be presented as the current one.
	 */
	private const VERSION = 'v2';

	/**
	 * Issue a token stamped with the current time.
	 *
	 * @param string $scope Form the token belongs to.
	 * @return string
	 */
	public static function issue( string $scope = 'reg' ): string {
		return self::make( time(), $scope, bin2hex( random_bytes( 16 ) ) );
	}

	/**
	 * Build a token for a given issue time (seam for deterministic tests).
	 *
	 * The nonce is what makes two forms rendered in the same second distinct.
	 * Signing only the timestamp meant every visitor who loaded a form during
	 * the same second received a byte-identical token, so single-use rejected
	 * all but the first of them — and a shared page cache handed one token to
	 * everybody. The scope is signed rather than merely prefixing the replay
	 * key, so a token issued by one form cannot be presented to another.
	 *
	 * @param int    $issued UNIX timestamp the token was issued.
	 * @param string $scope  Form the token belongs to.
	 * @param string $nonce  Per-render random value.
	 * @return string
	 */
	public static function make( int $issued, string $scope = 'reg', string $nonce = '' ): string {
		$payload = self::payload( $issued, $scope, $nonce );
		$hmac    = hash_hmac( 'sha256', $payload, self::secret() );

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Benign: compact form-safe encoding of the signed token, not obfuscation.
		return base64_encode( $payload . ':' . $hmac );
	}

	/**
	 * The signed part of a token.
	 *
	 * @param int    $issued UNIX timestamp.
	 * @param string $scope  Form the token belongs to.
	 * @param string $nonce  Per-render random value.
	 * @return string
	 */
	private static function payload( int $issued, string $scope, string $nonce ): string {
		return self::VERSION . '.' . $issued . '.' . preg_replace( '/[^a-z0-9_-]/', '', strtolower( $scope ) ) . '.' . $nonce;
	}

	/**
	 * Verify a token against the current time.
	 *
	 * @param string                $token    Raw token from the form.
	 * @param int                   $min_fill Minimum age in seconds (timing floor).
	 * @param int                   $max_age  Maximum age in seconds (expiry).
	 * @param StorageInterface|null $storage  When given, enforces single-use.
	 * @param string                $scope    Single-use namespace, so two forms
	 *                                        using this token cannot consume
	 *                                        each other's entries.
	 * @return bool
	 */
	public static function verify( string $token, int $min_fill, int $max_age, ?StorageInterface $storage = null, string $scope = 'reg' ): bool {
		return self::check( $token, time(), $min_fill, $max_age, $storage, $scope );
	}

	/**
	 * Verify a token against an explicit "now" (seam for deterministic tests).
	 *
	 * @param string                $token    Raw token from the form.
	 * @param int                   $now      Current UNIX timestamp.
	 * @param int                   $min_fill Minimum age in seconds (timing floor).
	 * @param int                   $max_age  Maximum age in seconds (expiry).
	 * @param StorageInterface|null $storage  When given, enforces single-use.
	 * @param string                $scope    Single-use namespace.
	 * @return bool
	 */
	public static function check( string $token, int $now, int $min_fill, int $max_age, ?StorageInterface $storage = null, string $scope = 'reg' ): bool {
		if ( '' === $token ) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Benign: decodes our own signed token, validated by HMAC below.
		$decoded = base64_decode( $token, true );

		if ( false === $decoded || ! str_contains( $decoded, ':' ) ) {
			return false;
		}

		[ $payload, $hmac ] = explode( ':', $decoded, 2 );

		$parts = explode( '.', $payload );

		if ( 4 !== count( $parts ) || self::VERSION !== $parts[0] || ! ctype_digit( $parts[1] ) ) {
			return false;
		}

		$expected = hash_hmac( 'sha256', $payload, self::secret() );

		if ( ! hash_equals( $expected, $hmac ) ) {
			return false;
		}

		// The scope is inside the signature, so a token issued for one form
		// cannot be presented to another — previously it only namespaced the
		// replay key, which a token never actually crossed.
		if ( preg_replace( '/[^a-z0-9_-]/', '', strtolower( $scope ) ) !== $parts[2] ) {
			return false;
		}

		$age = $now - (int) $parts[1];

		if ( $age < $min_fill || $age > $max_age ) {
			return false;
		}

		if ( null !== $storage ) {
			$key = $scope . '_tok_' . hash( 'sha256', $payload );

			// Atomic check-and-mark: the first use increments to 1 and passes;
			// any replay (or concurrent double-submit) increments to > 1 and is
			// rejected. A get()-then-set() had a TOCTOU window that let the same
			// token register several accounts.
			if ( $storage->increment( $key, $max_age ) > 1 ) {
				return false;
			}
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
