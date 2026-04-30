<?php
/**
 * Type-aware value caster shared by the CLI commands.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Casts raw CLI input to match the option's stored type and renders any value
 * back as a human-readable string for the table output.
 */
final class ValueCaster {

	/**
	 * Cast a raw string input to match the type of the default value.
	 *
	 * @param string $raw      Raw input from CLI.
	 * @param mixed  $type_ref Default value used to detect the target type.
	 * @return mixed
	 */
	public static function cast( string $raw, mixed $type_ref ): mixed {
		if ( is_bool( $type_ref ) ) {
			return in_array( strtolower( trim( $raw ) ), [ 'true', '1', 'yes', 'on' ], true );
		}

		if ( is_int( $type_ref ) ) {
			return (int) $raw;
		}

		if ( is_array( $type_ref ) ) {
			return self::parse_list( $raw );
		}

		return $raw;
	}

	/**
	 * Split a raw string on commas or newlines into a list of trimmed,
	 * non-empty entries.
	 *
	 * @param string $raw Raw input.
	 * @return array<int, string>
	 */
	public static function parse_list( string $raw ): array {
		$parts = preg_split( '/[\r\n,]+/', $raw );

		if ( false === $parts ) {
			return [];
		}

		$parts = array_map( 'trim', $parts );
		$parts = array_filter( $parts, static fn ( string $p ): bool => '' !== $p );

		return array_values( $parts );
	}

	/**
	 * Render any stored value as a human-readable string for table output.
	 *
	 * Arrays are rendered as `[a, b, c]` so the type is unambiguous in the
	 * table — earlier versions joined with `, ` and lost the type signal.
	 *
	 * @param mixed $value Stored value.
	 * @return string
	 */
	public static function stringify( mixed $value ): string {
		if ( is_bool( $value ) ) {
			return $value ? 'true' : 'false';
		}

		if ( is_array( $value ) ) {
			return '[' . implode( ', ', array_map( 'strval', $value ) ) . ']';
		}

		if ( null === $value ) {
			return '';
		}

		return (string) $value;
	}
}
