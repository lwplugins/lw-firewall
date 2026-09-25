<?php
/**
 * Filter parameter list parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

use LightweightPlugins\Firewall\OptionSchema;
use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Entries are `prefix` or `prefix|N`, where N is a per-prefix request limit
 * inside the rate-limit range. An empty list resets to the shipped defaults,
 * limits included.
 */
final class FilterParamsParser {

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

		if ( [] === $entries ) {
			return ParseResult::ok( Options::get_defaults()['filter_params'] );
		}

		$clean  = [];
		$errors = [];

		foreach ( $entries as $entry ) {
			$normal = self::normalize( $entry );

			if ( null === $normal ) {
				$errors[] = sprintf(
					/* translators: %s: the rejected entry */
					__( '"%s" is not valid. Use a parameter prefix, optionally followed by |N with N a positive whole number (e.g. add-to-cart|10).', 'lw-firewall' ),
					$entry
				);
				continue;
			}

			$clean[] = $normal;
		}

		return [] === $errors ? ParseResult::ok( array_values( array_unique( $clean ) ) ) : ParseResult::fail( $errors );
	}

	/**
	 * The canonical form of one entry, or null when malformed.
	 *
	 * @param string $entry Trimmed entry.
	 * @return string|null
	 */
	private static function normalize( string $entry ): ?string {
		$parts  = explode( '|', $entry );
		$prefix = trim( $parts[0] );

		if ( '' === $prefix || count( $parts ) > 2 ) {
			return null;
		}

		if ( 1 === count( $parts ) ) {
			return $prefix;
		}

		$limit      = trim( $parts[1] );
		[ , $max ]  = OptionSchema::ranges()['rate_limit'];
		$is_numeric = '' !== $limit && ctype_digit( $limit );

		if ( ! $is_numeric || (int) $limit < 1 || (int) $limit > $max ) {
			return null;
		}

		return $prefix . '|' . (int) $limit;
	}
}
