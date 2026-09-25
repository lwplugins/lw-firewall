<?php
/**
 * Shared helpers for the config CLI commands.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI\Support;

use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Settings\SettingsWriter;
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
	 * Resolve a list-option key to its STORED array value, or fail.
	 *
	 * The stored list, never the effective one: editing a list that is pinned
	 * in wp-config.php used to copy the pinned entries into the database.
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

		self::assert_not_pinned( $key );

		return SettingsWriter::stored_list( $key );
	}

	/**
	 * Validate and persist a setting (list or scalar), or fail with the
	 * input layer's messages.
	 *
	 * The shared write path also resyncs the .htaccess geo block and the geo
	 * cron, so a blocked_countries change reaches the Apache layer.
	 *
	 * @param string $key   Setting key.
	 * @param mixed  $value New value.
	 */
	private static function save_value( string $key, mixed $value ): void {
		$errors = SettingsWriter::write_one( $key, $value );

		if ( [] !== $errors ) {
			WP_CLI::error( "Invalid value for '{$key}': " . implode( ' ', $errors ) );
		}
	}

	/**
	 * Persist an updated list value, or fail.
	 *
	 * @param string             $key  Setting key.
	 * @param array<int, string> $list New list value.
	 */
	private static function save_list( string $key, array $list ): void {
		self::save_value( $key, array_values( $list ) );
	}

	/**
	 * Bail when a wp-config.php constant pins the key.
	 *
	 * @param string $key Setting key.
	 */
	private static function assert_not_pinned( string $key ): void {
		if ( in_array( $key, Options::overridden(), true ) ) {
			$constant = Options::CONST_PREFIX . strtoupper( $key );
			WP_CLI::error( "'{$key}' is pinned by {$constant} in wp-config.php. Remove the constant to change it." );
		}
	}
}
