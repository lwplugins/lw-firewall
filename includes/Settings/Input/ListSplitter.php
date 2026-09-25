<?php
/**
 * Splits a raw list value into entries.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns a textarea string or a JSON array into trimmed, non-empty entries.
 *
 * Unlike the old `array_filter()` without a callback, a literal "0" is an
 * entry like any other — it reaches the validator and is reported there
 * instead of vanishing.
 */
final class ListSplitter {

	/**
	 * Lines, and commas on a line.
	 */
	public const LINES_AND_COMMAS = '/[\r\n,]+/';

	/**
	 * Lines, commas and any whitespace (for values that never contain spaces).
	 */
	public const ANY_SEPARATOR = '/[\s,;]+/';

	/**
	 * Split a raw value.
	 *
	 * @param mixed  $raw     A string, or an array of scalars.
	 * @param string $pattern Separator regex used for strings.
	 * @return array<int, string>|null Entries, or null when the value is not a list.
	 */
	public static function split( mixed $raw, string $pattern = self::LINES_AND_COMMAS ): ?array {
		if ( is_string( $raw ) ) {
			$parts = preg_split( $pattern, $raw );
			$raw   = false === $parts ? [] : $parts;
		} elseif ( ! is_array( $raw ) ) {
			return null;
		}

		$entries = [];

		foreach ( $raw as $item ) {
			if ( ! is_scalar( $item ) ) {
				return null;
			}

			$entry = trim( (string) $item );

			if ( '' !== $entry ) {
				$entries[] = $entry;
			}
		}

		return $entries;
	}

	/**
	 * The refusal for a value that is neither a string nor a flat array.
	 *
	 * @return ParseResult
	 */
	public static function type_error(): ParseResult {
		return ParseResult::fail( [ __( 'Must be a list: one entry per line, or an array of strings.', 'lw-firewall' ) ] );
	}
}
