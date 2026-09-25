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
 * Renders any stored value as a human-readable string for the table output.
 * (Parsing CLI input is the settings input layer's job: Settings\Input.)
 */
final class ValueCaster {

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
