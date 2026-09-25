<?php
/**
 * The identity a client is counted and banned under.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Maps a client address to the key its counters and bans are stored under.
 *
 * An IPv4 address is its own subject. An IPv6 client is almost always handed a
 * whole /64 by its provider and can pick any of its 2^64 addresses per request,
 * so counting and banning per address gave such an attacker an unlimited
 * supply of fresh identities. Every rate counter, failure counter and ban is
 * therefore keyed by the /64 instead — written as a CIDR ("2001:db8:1:1::/64")
 * so the subject is readable in the ban list and is valid list syntax too.
 *
 * Whitelist and blacklist matching do not use this: those stay exact or CIDR,
 * exactly as the operator wrote them.
 */
final class IpSubject {

	/**
	 * Prefix length an IPv6 client is grouped by.
	 */
	public const IPV6_PREFIX = 64;

	/**
	 * The subject key for an address.
	 *
	 * An IPv4-mapped IPv6 address ("::ffff:203.0.113.7", which dual-stack
	 * sockets report) is folded to its IPv4 address — grouping it by /64 would
	 * put every IPv4 visitor into one shared "::/64" bucket. An existing /64 key
	 * is returned in canonical form, so the function is idempotent. Anything
	 * unparseable is returned unchanged.
	 *
	 * @param string $ip Client address, or a subject key.
	 * @return string
	 */
	public static function of( string $ip ): string {
		$suffix = '/' . self::IPV6_PREFIX;
		$host   = str_ends_with( $ip, $suffix ) ? substr( $ip, 0, -strlen( $suffix ) ) : $ip;
		$packed = filter_var( $host, FILTER_VALIDATE_IP ) ? inet_pton( $host ) : false;

		if ( false === $packed || ( $host !== $ip && 16 !== strlen( $packed ) ) ) {
			return $ip;
		}

		if ( 4 === strlen( $packed ) ) {
			return (string) inet_ntop( $packed );
		}

		if ( str_repeat( "\x00", 10 ) . "\xff\xff" === substr( $packed, 0, 12 ) ) {
			return (string) inet_ntop( substr( $packed, 12 ) );
		}

		return inet_ntop( substr( $packed, 0, 8 ) . str_repeat( "\x00", 8 ) ) . $suffix;
	}

	/**
	 * Validate an operator-supplied ban target (admin form, WP-CLI).
	 *
	 * Accepts any single address or an IPv6 /64 subject key — the form the ban
	 * list displays — and returns its subject.
	 *
	 * @param string $input Raw input.
	 * @return string Subject key, or '' when the input is neither.
	 */
	public static function parse( string $input ): string {
		$input = trim( $input );

		if ( filter_var( $input, FILTER_VALIDATE_IP ) || self::is_subject_key( $input ) ) {
			return self::of( $input );
		}

		return '';
	}

	/**
	 * Whether a string is an IPv6 /64 subject key (canonical or not).
	 *
	 * @param string $value Candidate.
	 * @return bool
	 */
	public static function is_subject_key( string $value ): bool {
		$suffix = '/' . self::IPV6_PREFIX;

		return str_ends_with( $value, $suffix )
			&& false !== filter_var( substr( $value, 0, -strlen( $suffix ) ), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
	}
}
