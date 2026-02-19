<?php
/**
 * Input Parser Trait for settings forms.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin;

use LightweightPlugins\Firewall\Options;

/**
 * Reusable textarea/input parsing methods.
 */
trait InputParserTrait {

	/**
	 * Parse filter params from textarea.
	 *
	 * @param array<string, mixed> $post_data Form data.
	 * @return array<int, string>
	 */
	private static function parse_filter_params( array $post_data ): array {
		if ( empty( $post_data['filter_params'] ) ) {
			return [ 'filter_', 'query_type_' ];
		}

		return self::textarea_to_lines( (string) $post_data['filter_params'] );
	}

	/**
	 * Parse blocked bots from textarea.
	 *
	 * @param array<string, mixed> $post_data Form data.
	 * @return array<int, string>
	 */
	private static function parse_blocked_bots( array $post_data ): array {
		if ( ! isset( $post_data['blocked_bots'] ) ) {
			return Options::get( 'blocked_bots' );
		}

		return self::textarea_to_lines( (string) $post_data['blocked_bots'] );
	}

	/**
	 * Parse a textarea into lines.
	 *
	 * @param array<string, mixed> $post_data Form data.
	 * @param string               $key       Field key.
	 * @return array<int, string>
	 */
	private static function parse_lines( array $post_data, string $key ): array {
		if ( empty( $post_data[ $key ] ) ) {
			return [];
		}

		return self::textarea_to_lines( (string) $post_data[ $key ] );
	}

	/**
	 * Parse country codes from textarea.
	 *
	 * @param array<string, mixed> $post_data Form data.
	 * @return array<int, string>
	 */
	private static function parse_country_codes( array $post_data ): array {
		if ( empty( $post_data['blocked_countries'] ) ) {
			return [];
		}

		$lines = self::textarea_to_lines( (string) $post_data['blocked_countries'] );
		$codes = [];

		foreach ( $lines as $line ) {
			$code = strtoupper( substr( $line, 0, 2 ) );

			if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
				$codes[] = $code;
			}
		}

		return array_values( array_unique( $codes ) );
	}

	/**
	 * Convert raw textarea value to array of lines.
	 *
	 * @param string $raw Raw textarea value.
	 * @return array<int, string>
	 */
	private static function textarea_to_lines( string $raw ): array {
		$raw   = sanitize_textarea_field( $raw );
		$lines = array_filter( array_map( 'trim', explode( "\n", $raw ) ) );

		return array_values( $lines );
	}
}
