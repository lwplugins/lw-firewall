<?php
/**
 * Which browser origins may run a passkey ceremony for this site.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Passkey;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exact origin match (scheme + host + port) against the origins of home_url()
 * and site_url(). WebAuthn itself would accept any subdomain of the RP ID; we
 * do not, so on a sub-domain multisite network (or any host serving
 * user-controlled subdomains) a sibling site cannot host a ceremony for this
 * one. A site that really signs in from another subdomain adds that origin via
 * the `lw_firewall_passkey_allowed_origins` filter (array of origin strings,
 * e.g. "https://login.example.com"); every entry is validated and must still
 * lie under the RP ID. Plain http is allowed only for localhost.
 */
final class OriginPolicy {

	public const FILTER = 'lw_firewall_passkey_allowed_origins';

	/**
	 * Allowed origins, normalized and deduplicated.
	 *
	 * @return string[]
	 */
	public static function origins(): array {
		$list = array();
		foreach ( array( home_url(), site_url() ) as $url ) {
			$origin = self::normalize( (string) $url, false );
			if ( null !== $origin ) {
				$list[] = $origin;
			}
		}

		/**
		 * Filters the extra origins allowed to run passkey ceremonies.
		 *
		 * @param mixed    $extra Extra origins, an array of origin strings (default none).
		 * @param string[] $base  Origins derived from home_url() and site_url().
		 */
		$extra = apply_filters( 'lw_firewall_passkey_allowed_origins', array(), $list );
		if ( is_array( $extra ) ) {
			foreach ( $extra as $value ) {
				$origin = is_string( $value ) ? self::normalize( $value, true ) : null;
				if ( null !== $origin ) {
					$list[] = $origin;
				}
			}
		}

		return array_values( array_unique( $list ) );
	}

	/**
	 * Whether a clientDataJSON origin is allowed.
	 *
	 * @param string $origin Origin from clientDataJSON.
	 */
	public static function allowed( string $origin ): bool {
		$normalized = self::normalize( $origin, true );

		return null !== $normalized && in_array( $normalized, self::origins(), true );
	}

	/**
	 * Canonical "scheme://host[:port]" (default port omitted), or null.
	 *
	 * @param string $url  URL or origin.
	 * @param bool   $bare True: must be a bare origin (no path, query, credentials).
	 */
	private static function normalize( string $url, bool $bare ): ?string {
		$parts = wp_parse_url( $url );
		$rp_id = WebAuthnFactory::rp_id();
		if ( '' === $rp_id || ! is_array( $parts ) || ! isset( $parts['scheme'], $parts['host'] ) ) {
			return null;
		}
		if ( $bare && ( isset( $parts['user'] ) || isset( $parts['pass'] ) || isset( $parts['query'] ) || isset( $parts['fragment'] )
			|| ! in_array( $parts['path'] ?? '', array( '', '/' ), true ) ) ) {
			return null;
		}

		$scheme = strtolower( (string) $parts['scheme'] );
		$host   = strtolower( (string) $parts['host'] );
		if ( 'https' !== $scheme && ! ( 'http' === $scheme && 'localhost' === $host ) ) {
			return null;
		}
		if ( $host !== $rp_id && ! str_ends_with( $host, '.' . $rp_id ) ) {
			return null;
		}

		$port = isset( $parts['port'] ) ? (int) $parts['port'] : null;
		if ( ( 'https' === $scheme && 443 === $port ) || ( 'http' === $scheme && 80 === $port ) ) {
			$port = null;
		}

		return $scheme . '://' . $host . ( null === $port ? '' : ':' . $port );
	}
}
