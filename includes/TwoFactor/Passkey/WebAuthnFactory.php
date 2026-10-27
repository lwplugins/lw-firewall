<?php
/**
 * Builds the WebAuthn library instance and owns the relying-party settings.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Passkey;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Relying party = this site (allowed origins: OriginPolicy). The RP ID is the host of home_url(): passkeys are
 * bound to it by the authenticator, so moving the site to a new domain makes
 * every registered passkey unusable (inherent to WebAuthn) — users then sign
 * in with their password + other factor and register new passkeys.
 */
final class WebAuthnFactory {

	/**
	 * Strauss-scoped copy shipped in the release ZIP.
	 */
	public const PREFIXED_CLASS = 'LightweightPlugins\\Firewall\\Vendor\\lbuchs\\WebAuthn\\WebAuthn';

	/**
	 * Unscoped class (Composer installs, development, tests).
	 */
	public const LIBRARY_CLASS = 'lbuchs\\WebAuthn\\WebAuthn';

	/**
	 * Accepted attestation formats.
	 */
	public const FORMATS = array( 'none', 'packed', 'fido-u2f', 'apple', 'android-key', 'tpm' );

	/**
	 * Library class to use, or null when passkeys are unavailable.
	 */
	public static function class_name(): ?string {
		foreach ( array( self::PREFIXED_CLASS, self::LIBRARY_CLASS ) as $class ) {
			if ( class_exists( $class ) ) {
				return $class;
			}
		}

		return null;
	}

	/**
	 * Whether passkeys can work on this install.
	 */
	public static function available(): bool {
		return null !== self::class_name() && '' !== self::rp_id();
	}

	/**
	 * A fresh library instance (one per ceremony: it caches its challenge).
	 *
	 * @return \lbuchs\WebAuthn\WebAuthn The scoped copy has the same API.
	 * @throws \RuntimeException When the library or the site host is missing.
	 */
	public static function create(): object {
		$class = self::class_name();
		$rp_id = self::rp_id();
		if ( null === $class || '' === $rp_id ) {
			throw new \RuntimeException( 'Passkeys unavailable: WebAuthn library or site host missing.' );
		}

		$name = trim( wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES ) );

		// Base64url mode: every binary field of the options JSON is base64url text.
		return new $class( '' !== $name ? $name : $rp_id, $rp_id, self::FORMATS, true );
	}

	/**
	 * Relying-party ID: the lowercased host of home_url().
	 */
	public static function rp_id(): string {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );

		return is_string( $host ) ? strtolower( $host ) : '';
	}

	/**
	 * Run library code, then restore the library's global encoding flag.
	 *
	 * The library constructor sets the static ByteBuffer::$useBase64UrlEncoding;
	 * in unprefixed (Composer) installs another plugin may share that class, so
	 * the previous value is put back even when $fn throws.
	 *
	 * @template T
	 * @param callable(): T $fn Library work.
	 * @return T
	 */
	public static function isolated( callable $fn ): mixed {
		$class  = self::class_name();
		$buffer = null === $class ? '' : substr( $class, 0, (int) strrpos( $class, '\\' ) ) . '\\Binary\\ByteBuffer';
		if ( '' === $buffer || ! class_exists( $buffer ) || ! property_exists( $buffer, 'useBase64UrlEncoding' ) ) {
			return $fn();
		}

		$previous = $buffer::$useBase64UrlEncoding; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Library property name.
		try {
			return $fn();
		} finally {
			$buffer::$useBase64UrlEncoding = $previous; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Library property name.
		}
	}
}
