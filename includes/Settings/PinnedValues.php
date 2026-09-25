<?php
/**
 * Keeps wp-config.php pinned keys out of a bulk write.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A bulk write (reset to defaults) must leave a pinned key's stored value
 * exactly as it was: the constant owns that key while it is defined.
 */
final class PinnedValues {

	/**
	 * Replace every pinned key in the candidate values with its stored value.
	 *
	 * @param array<string, mixed> $values Candidate values.
	 * @param array<string, mixed> $stored Stored values.
	 * @param array<int, string>   $locked Pinned keys.
	 * @return array<string, mixed>
	 */
	public static function keep( array $values, array $stored, array $locked ): array {
		foreach ( $locked as $key ) {
			if ( array_key_exists( $key, $stored ) ) {
				$values[ $key ] = $stored[ $key ];
			} else {
				unset( $values[ $key ] );
			}
		}

		return $values;
	}
}
