<?php
/**
 * Whole-number parser with a range.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Accepts an integer (or its decimal string) inside the OptionSchema range.
 * Anything outside is an error rather than a silent clamp.
 */
final class IntParser {

	/**
	 * Parse a raw value.
	 *
	 * @param mixed $raw Raw value.
	 * @param int   $min Lowest allowed value.
	 * @param int   $max Highest allowed value.
	 * @return ParseResult
	 */
	public static function parse( mixed $raw, int $min, int $max ): ParseResult {
		$number = self::to_int( $raw );

		if ( null === $number ) {
			return ParseResult::fail( [ __( 'Must be a whole number.', 'lw-firewall' ) ] );
		}

		if ( $number < $min || $number > $max ) {
			return ParseResult::fail(
				[
					/* translators: 1: lowest allowed number, 2: highest allowed number */
					sprintf( __( 'Must be between %1$d and %2$d.', 'lw-firewall' ), $min, $max ),
				]
			);
		}

		return ParseResult::ok( $number );
	}

	/**
	 * The integer a raw value stands for, or null.
	 *
	 * @param mixed $raw Raw value.
	 * @return int|null
	 */
	private static function to_int( mixed $raw ): ?int {
		if ( is_int( $raw ) ) {
			return $raw;
		}

		if ( is_float( $raw ) && floor( $raw ) === $raw && abs( $raw ) < PHP_INT_MAX ) {
			return (int) $raw;
		}

		if ( is_string( $raw ) && 1 === preg_match( '/^-?\d{1,15}$/', trim( $raw ) ) ) {
			return (int) trim( $raw );
		}

		return null;
	}
}
