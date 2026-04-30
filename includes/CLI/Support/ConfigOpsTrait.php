<?php
/**
 * Shared helpers for the config CLI commands.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI\Support;

use LightweightPlugins\Firewall\Options;
use WP_CLI;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Validation + persistence helpers used by both ConfigCommand and
 * ConfigItemsCommand.
 */
trait ConfigOpsTrait {

	/**
	 * Bail with a friendly error if the key is unknown.
	 *
	 * @param string                    $key      Setting key.
	 * @param array<string, mixed>|null $defaults Pre-fetched defaults to avoid a repeat call.
	 */
	private static function assert_known_key( string $key, ?array $defaults = null ): void {
		$defaults ??= Options::get_defaults();

		if ( ! array_key_exists( $key, $defaults ) ) {
			WP_CLI::error( "Unknown setting key: '{$key}'" );
		}
	}

	/**
	 * Resolve a list-option key to its current array value, or fail.
	 *
	 * @param string $key Setting key.
	 * @return array<int, string>
	 */
	private static function resolve_list_or_fail( string $key ): array {
		$defaults = Options::get_defaults();
		self::assert_known_key( $key, $defaults );

		if ( ! is_array( $defaults[ $key ] ) ) {
			WP_CLI::error( "Setting '{$key}' is not a list option. Use 'config set' instead." );
		}

		$value = Options::get( $key );

		return is_array( $value ) ? array_values( $value ) : [];
	}

	/**
	 * Persist an updated list value, or fail.
	 *
	 * @param string             $key  Setting key.
	 * @param array<int, string> $list New list value.
	 */
	private static function save_list( string $key, array $list ): void {
		$current         = Options::get_all();
		$current[ $key ] = array_values( $list );

		if ( ! Options::save( $current ) ) {
			WP_CLI::error( "Failed to update '{$key}'." );
		}
	}
}
