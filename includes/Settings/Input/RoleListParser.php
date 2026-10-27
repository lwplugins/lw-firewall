<?php
/**
 * User role slug list parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Accepts role slugs (letters, digits, underscore, hyphen), in any case,
 * separated by lines, commas or spaces. An entry that would be altered by
 * sanitize_key() beyond lowercasing is rejected and reported, not repaired.
 */
final class RoleListParser {

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

		$roles  = [];
		$errors = [];

		foreach ( $entries as $entry ) {
			$slug = sanitize_key( $entry );

			if ( '' !== $slug && strtolower( $entry ) === $slug ) {
				$roles[] = $slug;
				continue;
			}

			/* translators: %s: the rejected entry */
			$errors[] = sprintf( __( '"%s" is not a valid role slug.', 'lw-firewall' ), $entry );
		}

		return [] === $errors ? ParseResult::ok( array_values( array_unique( $roles ) ) ) : ParseResult::fail( $errors );
	}
}
