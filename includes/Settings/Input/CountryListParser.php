<?php
/**
 * Country code list parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

use LightweightPlugins\Firewall\Data\Countries;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Accepts assigned ISO 3166-1 alpha-2 codes only, in any case, separated by
 * lines, commas or spaces. A name like "Germany" is rejected and reported —
 * never truncated into a different country's code.
 */
final class CountryListParser {

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

		$codes  = [];
		$errors = [];

		foreach ( $entries as $entry ) {
			$code = strtoupper( $entry );

			if ( 2 === strlen( $code ) && Countries::exists( $code ) ) {
				$codes[] = $code;
				continue;
			}

			/* translators: %s: the rejected entry */
			$errors[] = sprintf( __( '"%s" is not a two-letter ISO 3166-1 country code.', 'lw-firewall' ), $entry );
		}

		return [] === $errors ? ParseResult::ok( array_values( array_unique( $codes ) ) ) : ParseResult::fail( $errors );
	}
}
