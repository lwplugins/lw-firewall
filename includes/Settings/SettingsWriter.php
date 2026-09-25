<?php
/**
 * Writes validated settings.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings;

use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Settings\Input\OptionInput;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The one write path behind the REST save, the import and WP-CLI.
 *
 * Every write starts from the STORED settings (never the effective ones, so a
 * wp-config.php pin is not copied into the database), leaves pinned keys
 * alone, and runs the post-save side effects.
 */
final class SettingsWriter {

	/**
	 * Persist already-validated values over the stored settings.
	 *
	 * @param array<string, mixed> $values Parsed values keyed by option.
	 * @return void
	 */
	public static function save( array $values ): void {
		$before = Options::get_stored();

		Options::save( $values );
		SaveEffects::apply( $before );
	}

	/**
	 * Validate and write one setting.
	 *
	 * @param string $key Option key.
	 * @param mixed  $raw Raw value (string from the CLI, or a list).
	 * @return array<int, string> Error messages; empty on success.
	 */
	public static function write_one( string $key, mixed $raw ): array {
		if ( ! array_key_exists( $key, Options::get_defaults() ) ) {
			/* translators: %s: setting key */
			return [ sprintf( __( 'Unknown setting: %s.', 'lw-firewall' ), $key ) ];
		}

		if ( in_array( $key, Options::overridden(), true ) ) {
			return [
				sprintf(
					/* translators: %s: constant name */
					__( 'This setting is pinned by %s in wp-config.php. Remove the constant to change it.', 'lw-firewall' ),
					Options::CONST_PREFIX . strtoupper( $key )
				),
			];
		}

		$result = OptionInput::parse_value( $key, $raw );

		if ( ! $result->is_valid() ) {
			return $result->errors();
		}

		self::save( [ $key => $result->value() ] );

		return [];
	}

	/**
	 * The stored (not effective) value of a list setting.
	 *
	 * @param string $key Option key.
	 * @return array<int, string>
	 */
	public static function stored_list( string $key ): array {
		$value = Options::get_stored()[ $key ] ?? [];

		return is_array( $value ) ? array_values( array_map( 'strval', $value ) ) : [];
	}

	/**
	 * Reset every setting to its default, except the ones pinned in
	 * wp-config.php, which keep their stored value untouched.
	 *
	 * @return void
	 */
	public static function reset(): void {
		self::save( PinnedValues::keep( Options::get_defaults(), Options::get_stored(), Options::overridden() ) );
	}
}
