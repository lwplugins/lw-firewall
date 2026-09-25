<?php
/**
 * Enum parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Accepts one of a fixed set of lower-case values.
 */
final class EnumParser {

	/**
	 * Parse a raw value.
	 *
	 * @param mixed              $raw     Raw value.
	 * @param array<int, string> $allowed Allowed values.
	 * @return ParseResult
	 */
	public static function parse( mixed $raw, array $allowed ): ParseResult {
		$value = is_scalar( $raw ) && ! is_bool( $raw ) ? strtolower( trim( (string) $raw ) ) : null;

		if ( null !== $value && in_array( $value, $allowed, true ) ) {
			return ParseResult::ok( $value );
		}

		return ParseResult::fail(
			[
				/* translators: %s: comma-separated list of allowed values */
				sprintf( __( 'Must be one of: %s.', 'lw-firewall' ), implode( ', ', $allowed ) ),
			]
		);
	}
}
