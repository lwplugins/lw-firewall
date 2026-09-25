<?php
/**
 * Settings read/write for the admin API.
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
 * Reads the settings as typed values and applies partial, atomic updates.
 *
 * A key the client did not send keeps its stored value (never the classic
 * form's "absent checkbox = false"). If any submitted field is invalid,
 * nothing is saved.
 */
final class SettingsStore {

	/**
	 * The effective settings (wp-config.php pins included), every key typed
	 * like its default.
	 *
	 * @return array<string, mixed>
	 */
	public static function current(): array {
		return self::typed( Options::get_all(), Options::get_defaults() );
	}

	/**
	 * Apply a partial update.
	 *
	 * @param array<string|int, mixed> $body Submitted key => value pairs.
	 * @return array<string, array<int, string>> Messages per invalid field; empty when saved.
	 */
	public static function save( array $body ): array {
		$report = OptionInput::parse( $body, Options::overridden() );

		if ( $report->has_errors() ) {
			return $report->errors();
		}

		if ( [] !== $report->values() ) {
			SettingsWriter::save( $report->values() );
		}

		return [];
	}

	/**
	 * Cast every default key to its default's type for the JSON response.
	 *
	 * @param array<string, mixed> $values   Option values.
	 * @param array<string, mixed> $defaults Option defaults.
	 * @return array<string, mixed>
	 */
	public static function typed( array $values, array $defaults ): array {
		$typed = [];

		foreach ( $defaults as $key => $default ) {
			$value = array_key_exists( $key, $values ) ? $values[ $key ] : $default;

			if ( is_bool( $default ) ) {
				$typed[ $key ] = (bool) $value;
			} elseif ( is_int( $default ) ) {
				$typed[ $key ] = is_numeric( $value ) ? (int) $value : $default;
			} elseif ( is_array( $default ) ) {
				$typed[ $key ] = is_array( $value ) ? array_values( array_map( 'strval', array_filter( $value, 'is_scalar' ) ) ) : [];
			} else {
				$typed[ $key ] = is_scalar( $value ) ? (string) $value : (string) $default;
			}
		}

		return $typed;
	}
}
