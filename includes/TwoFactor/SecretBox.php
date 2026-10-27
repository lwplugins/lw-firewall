<?php
/**
 * Authenticated encryption for secrets stored at rest (TOTP secrets).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Seals and opens strings with XSalsa20-Poly1305 (sodium secretbox), keyed from the site salt.
 */
final class SecretBox {

	/**
	 * Encrypt a string.
	 *
	 * @param string $plain Plain text.
	 * @return string base64( nonce . ciphertext ).
	 */
	public static function seal( string $plain ): string {
		$key   = self::key();
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Storage encoding of a ciphertext, not obfuscation.
		$out = base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, $key ) );
		sodium_memzero( $key );

		return $out;
	}

	/**
	 * Decrypt a string produced by seal().
	 *
	 * @param string $sealed Sealed value.
	 * @return string|null Plain text, or null when the input is corrupt or made with another key.
	 */
	public static function open( string $sealed ): ?string {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Strict decode of our own ciphertext.
		$raw = base64_decode( $sealed, true );
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES - 1 ) {
			return null;
		}

		$nonce = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$key   = self::key();
		$plain = sodium_crypto_secretbox_open( $box, $nonce, $key );
		sodium_memzero( $key );

		return false === $plain ? null : $plain;
	}

	/**
	 * Derive the 32 byte key from the site salt.
	 *
	 * @return string
	 */
	private static function key(): string {
		return sodium_crypto_generichash( wp_salt( 'secure_auth' ) . 'lw-firewall-2fa', '', 32 );
	}
}
