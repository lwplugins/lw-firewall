<?php
/**
 * Strict, canonical base64url codec (RFC 4648 §5, no padding).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Passkey;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Every binary WebAuthn field crosses the wire in this encoding.
 */
final class Base64Url {

	/**
	 * Encode binary data.
	 *
	 * @param string $bin Binary data.
	 */
	public static function encode( string $bin ): string {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- WebAuthn wire format, not obfuscation.
		return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' );
	}

	/**
	 * Decode, accepting only the canonical unpadded form.
	 *
	 * One binary value has exactly one accepted spelling, so a credential id
	 * can be compared and looked up as text.
	 *
	 * @param string $text Base64url text.
	 * @return string|null Binary data, or null when malformed.
	 */
	public static function decode( string $text ): ?string {
		if ( 1 !== preg_match( '/^[A-Za-z0-9_-]*$/D', $text ) || 1 === strlen( $text ) % 4 ) {
			return null;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- WebAuthn wire format, not obfuscation.
		$bin = base64_decode( strtr( $text, '-_', '+/' ), true );
		if ( false === $bin || self::encode( $bin ) !== $text ) {
			return null;
		}

		return $bin;
	}
}
