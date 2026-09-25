<?php
/**
 * In-memory wp_options double for unit tests.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Support;

use Brain\Monkey\Functions;

/**
 * Wires get_option / update_option / delete_option to an array so code that
 * reads and writes options (the ban index, the settings) can be exercised
 * without WordPress.
 */
final class OptionStore {

	/**
	 * Stored options.
	 *
	 * @var array<string, mixed>
	 */
	public array $data = array();

	/**
	 * Install the option stubs. Call from a test's setUp() after Monkey\setUp().
	 *
	 * @param array<string, mixed> $initial Initial option values.
	 * @return self
	 */
	public static function install( array $initial = array() ): self {
		$store       = new self();
		$store->data = $initial;

		Functions\when( 'get_option' )->alias(
			static fn ( string $key, $fallback = false ) => array_key_exists( $key, $store->data ) ? $store->data[ $key ] : $fallback
		);
		Functions\when( 'update_option' )->alias(
			static function ( string $key, $value ) use ( $store ): bool {
				$store->data[ $key ] = $value;
				return true;
			}
		);
		Functions\when( 'delete_option' )->alias(
			static function ( string $key ) use ( $store ): bool {
				unset( $store->data[ $key ] );
				return true;
			}
		);

		return $store;
	}
}
