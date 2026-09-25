<?php
/**
 * Strict boolean parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Accepts real booleans and their usual spellings; a JSON "false" string is
 * false, not truthy.
 */
final class BoolParser {

	private const TRUE_WORDS  = [ '1', 'true', 'yes', 'on' ];
	private const FALSE_WORDS = [ '0', 'false', 'no', 'off', '' ];

	/**
	 * Parse a raw value.
	 *
	 * @param mixed $raw Raw value.
	 * @return ParseResult
	 */
	public static function parse( mixed $raw ): ParseResult {
		if ( is_bool( $raw ) ) {
			return ParseResult::ok( $raw );
		}

		if ( 1 === $raw || 0 === $raw ) {
			return ParseResult::ok( 1 === $raw );
		}

		if ( is_string( $raw ) ) {
			$word = strtolower( trim( $raw ) );

			if ( in_array( $word, self::TRUE_WORDS, true ) ) {
				return ParseResult::ok( true );
			}

			if ( in_array( $word, self::FALSE_WORDS, true ) ) {
				return ParseResult::ok( false );
			}
		}

		return ParseResult::fail( [ __( 'Must be on or off (true or false).', 'lw-firewall' ) ] );
	}
}
