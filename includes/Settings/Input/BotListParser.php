<?php
/**
 * Blocked user-agent list parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * User-agent substrings, one per line. Blank entries never survive (an empty
 * needle would match — and 403 — every request), duplicates are dropped
 * case-insensitively because matching is case-insensitive.
 */
final class BotListParser {

	/**
	 * Longest accepted entry.
	 */
	public const MAX_LENGTH = 200;

	/**
	 * Parse a raw list.
	 *
	 * @param mixed $raw Textarea string or array.
	 * @return ParseResult
	 */
	public static function parse( mixed $raw ): ParseResult {
		$entries = ListSplitter::split( $raw );

		if ( null === $entries ) {
			return ListSplitter::type_error();
		}

		$clean  = [];
		$errors = [];

		foreach ( $entries as $entry ) {
			$entry = trim( (string) preg_replace( '/[\x00-\x1F\x7F]+/', '', $entry ) );

			if ( strlen( $entry ) > self::MAX_LENGTH ) {
				/* translators: %d: maximum number of characters */
				$errors[] = sprintf( __( 'An entry is longer than %d characters.', 'lw-firewall' ), self::MAX_LENGTH );
				continue;
			}

			if ( '' !== $entry && ! isset( $clean[ strtolower( $entry ) ] ) ) {
				$clean[ strtolower( $entry ) ] = $entry;
			}
		}

		return [] === $errors ? ParseResult::ok( array_values( $clean ) ) : ParseResult::fail( $errors );
	}
}
