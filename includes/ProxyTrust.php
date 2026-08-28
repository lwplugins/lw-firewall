<?php
/**
 * Trusted reverse-proxy resolution.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

use LightweightPlugins\Firewall\Rules\IpMatcher;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolves the real client address when the site sits behind a reverse proxy.
 *
 * This is opt-in on purpose. A forwarded-for header is client-controlled unless
 * the hop that set it is known, so trusting one by default would let anyone
 * pick their own IP — and with it their own rate-limit bucket, ban status and
 * country. Nothing here does anything until an operator lists the proxies.
 *
 * Without it, the common "nginx in front of Apache on the same host" layout
 * makes every request arrive as 127.0.0.1: one shared bucket for the whole
 * internet, and a loopback address that the worker treats as the server's own.
 */
final class ProxyTrust {

	/**
	 * Headers an operator may nominate, mapped to their $_SERVER key.
	 *
	 * Restricted to a known set so a typo cannot point the resolver at an
	 * arbitrary, attacker-supplied header.
	 *
	 * @var array<string, string>
	 */
	private const HEADERS = [
		'x-forwarded-for' => 'HTTP_X_FORWARDED_FOR',
		'x-real-ip'       => 'HTTP_X_REAL_IP',
		'forwarded'       => 'HTTP_FORWARDED',
	];

	/**
	 * Whether a trusted-proxy configuration exists at all.
	 *
	 * @param array<int, string> $proxies Configured proxy addresses/ranges.
	 * @return bool
	 */
	public static function is_configured( array $proxies ): bool {
		return ! empty( array_filter( array_map( 'trim', $proxies ) ) );
	}

	/**
	 * Resolve the client address from a forwarded header.
	 *
	 * The chain is read right to left, skipping hops that are themselves
	 * trusted. The first address that is not a trusted proxy is the closest
	 * one the infrastructure actually vouches for; everything to its left was
	 * written by something we do not control and is ignored.
	 *
	 * @param string             $remote_addr The connecting address.
	 * @param array<int, string> $proxies     Trusted proxy addresses/ranges.
	 * @param string             $header      Configured header name.
	 * @return string Resolved client IP, or '' when nothing trustworthy was found.
	 */
	public static function resolve( string $remote_addr, array $proxies, string $header ): string {
		if ( ! self::is_configured( $proxies ) || ! IpMatcher::matches( $remote_addr, $proxies ) ) {
			return '';
		}

		$key = self::HEADERS[ strtolower( trim( $header ) ) ] ?? self::HEADERS['x-forwarded-for'];

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Each candidate is validated by filter_var below.
		$raw = isset( $_SERVER[ $key ] ) ? (string) $_SERVER[ $key ] : '';

		if ( '' === $raw ) {
			return '';
		}

		foreach ( array_reverse( self::candidates( $raw ) ) as $candidate ) {
			if ( ! IpMatcher::matches( $candidate, $proxies ) ) {
				return $candidate;
			}
		}

		return '';
	}

	/**
	 * Split a forwarded header into validated addresses.
	 *
	 * Handles both the comma-separated `X-Forwarded-For` list and RFC 7239
	 * `Forwarded: for=...` syntax, including bracketed IPv6 and port suffixes.
	 *
	 * @param string $raw Raw header value.
	 * @return array<int, string>
	 */
	public static function candidates( string $raw ): array {
		$out = [];

		foreach ( explode( ',', $raw ) as $part ) {
			$part = trim( $part );

			// RFC 7239: for="[2001:db8::1]:443";proto=https
			if ( false !== stripos( $part, 'for=' ) ) {
				$part = (string) preg_replace( '/^.*?for=/i', '', $part );
				$part = (string) preg_replace( '/;.*$/', '', $part );
			}

			$part = trim( $part, " \t\"'" );

			// Bracketed IPv6, optionally with a port.
			if ( str_starts_with( $part, '[' ) ) {
				$part = (string) preg_replace( '/^\[([^\]]+)\].*$/', '$1', $part );
			} elseif ( substr_count( $part, ':' ) === 1 ) {
				// IPv4 with a port — an IPv6 address has more than one colon.
				$part = (string) strtok( $part, ':' );
			}

			if ( '' !== $part && filter_var( $part, FILTER_VALIDATE_IP ) ) {
				$out[] = $part;
			}
		}

		return $out;
	}

	/**
	 * Whether an address is one nobody on the internet can be reaching us from.
	 *
	 * A front-end request whose resolved client IP is loopback or private means
	 * the real address is being hidden by a proxy that is not configured here —
	 * the state in which every visitor shares one bucket and the firewall is
	 * effectively off. The Status screen says so rather than looking healthy.
	 *
	 * @param string $ip Resolved client IP.
	 * @return bool
	 */
	public static function is_non_routable( string $ip ): bool {
		if ( '' === $ip ) {
			return true;
		}

		return ! filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		);
	}
}
