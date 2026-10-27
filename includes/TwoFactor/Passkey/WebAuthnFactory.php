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
 * Relying party = this site. The RP ID is the host of home_url(): passkeys are
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
	 * Whether a clientDataJSON origin belongs to this RP.
	 *
	 * Stricter than the library's own suffix match: the host must equal the
	 * RP ID or be a subdomain of it (dot boundary), over https (http only for
	 * localhost).
	 *
	 * @param string $origin Origin from clientDataJSON.
	 */
	public static function origin_allowed( string $origin ): bool {
		$rp_id = self::rp_id();
		$parts = wp_parse_url( $origin );
		if ( '' === $rp_id || ! is_array( $parts ) || ! isset( $parts['scheme'], $parts['host'] ) ) {
			return false;
		}

		$scheme = strtolower( (string) $parts['scheme'] );
		$host   = strtolower( (string) $parts['host'] );
		if ( 'https' !== $scheme && ! ( 'http' === $scheme && 'localhost' === $rp_id ) ) {
			return false;
		}

		return $host === $rp_id || str_ends_with( $host, '.' . $rp_id );
	}
}
