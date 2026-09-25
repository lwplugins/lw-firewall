<?php
/**
 * IP address / CIDR range list parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Validates whitelist, blacklist and trusted-proxy entries: an IPv4/IPv6
 * address, or one followed by a decimal prefix inside its family's width.
 * Every invalid entry is reported; nothing is stored silently unmatched.
 */
final class IpListParser {

	/**
	 * Parse a raw list.
	 *
	 * @param mixed $raw Textarea string or array.
	 * @return ParseResult
	 */
	public static function parse( mixed $raw ): ParseResult {
		$entries = ListSplitter::split( $raw, ListSplitter::ANY_SEPARATOR );

		if ( null === $entries ) {
			return ListSplitter::type_error();
		}

		$errors = [];

		foreach ( $entries as $entry ) {
			if ( ! self::is_valid( $entry ) ) {
				/* translators: %s: the rejected entry */
				$errors[] = sprintf( __( '"%s" is not a valid IP address or CIDR range.', 'lw-firewall' ), $entry );
			}
		}

		return [] === $errors ? ParseResult::ok( array_values( array_unique( $entries ) ) ) : ParseResult::fail( $errors );
	}

	/**
	 * Whether one entry is an address or a well-formed CIDR range.
	 *
	 * @param string $entry Trimmed entry.
	 * @return bool
	 */
	public static function is_valid( string $entry ): bool {
		$parts = explode( '/', $entry );

		if ( count( $parts ) > 2 || false === filter_var( $parts[0], FILTER_VALIDATE_IP ) ) {
			return false;
		}

		if ( 1 === count( $parts ) ) {
			return true;
		}

		$width = str_contains( $parts[0], ':' ) ? 128 : 32;

		return '' !== $parts[1] && ctype_digit( $parts[1] ) && (int) $parts[1] <= $width;
	}
}
