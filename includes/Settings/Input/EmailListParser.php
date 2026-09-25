<?php
/**
 * Alert recipient list parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Validates every address and stores them as one comma-separated string
 * (the format AlertMailer::recipients() reads). An invalid address is
 * reported instead of being dropped.
 */
final class EmailListParser {

	/**
	 * Parse a raw list.
	 *
	 * @param mixed $raw String (commas, semicolons or lines) or array.
	 * @return ParseResult
	 */
	public static function parse( mixed $raw ): ParseResult {
		$entries = ListSplitter::split( $raw, '/[\r\n,;]+/' );

		if ( null === $entries ) {
			return ListSplitter::type_error();
		}

		$clean  = [];
		$errors = [];

		foreach ( $entries as $entry ) {
			if ( false === is_email( $entry ) ) {
				/* translators: %s: the rejected entry */
				$errors[] = sprintf( __( '"%s" is not a valid email address.', 'lw-firewall' ), $entry );
				continue;
			}

			$clean[ strtolower( $entry ) ] = $entry;
		}

		return [] === $errors ? ParseResult::ok( implode( ', ', $clean ) ) : ParseResult::fail( $errors );
	}
}
