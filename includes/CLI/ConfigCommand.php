<?php
/**
 * Firewall config CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\Options;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage firewall configuration.
 */
final class ConfigCommand {

	/**
	 * List all configuration values.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall config list
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 *
	 * @subcommand list
	 */
	public function list_config( array $args, array $assoc_args ): void {
		$format  = Utils\get_flag_value( $assoc_args, 'format', 'table' );
		$options = Options::get_all();
		$items   = [];

		foreach ( $options as $key => $value ) {
			$display = $value;
			if ( is_array( $value ) ) {
				$display = implode( ', ', $value );
			} elseif ( is_bool( $value ) ) {
				$display = $value ? 'true' : 'false';
			}

			$items[] = [
				'key'   => $key,
				'value' => (string) $display,
			];
		}

		Utils\format_items( $format, $items, [ 'key', 'value' ] );
	}

	/**
	 * Set a configuration value.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The setting key.
	 *
	 * <value>
	 * : The setting value.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall config set rate_limit 50
	 *     $ wp lw-firewall config set enabled true
	 *     $ wp lw-firewall config set storage apcu
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function set( array $args, array $assoc_args ): void {
		[ $key, $raw_value ] = $args;

		$defaults = Options::get_defaults();

		if ( ! array_key_exists( $key, $defaults ) ) {
			WP_CLI::error( "Unknown setting key: '{$key}'" );
		}

		$value = self::cast_value( $raw_value, $defaults[ $key ] );

		$current         = Options::get_all();
		$current[ $key ] = $value;

		if ( Options::save( $current ) ) {
			WP_CLI::success( "Set '{$key}' to '{$raw_value}'." );
		} else {
			WP_CLI::error( "Failed to update '{$key}'." );
		}
	}

	/**
	 * Reset all settings to defaults.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Skip confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall config reset --yes
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function reset( array $args, array $assoc_args ): void {
		WP_CLI::confirm( 'Reset all firewall settings to defaults?', $assoc_args );

		if ( Options::save( Options::get_defaults() ) ) {
			WP_CLI::success( 'All settings reset to defaults.' );
		} else {
			WP_CLI::error( 'Failed to reset settings.' );
		}
	}

	/**
	 * Cast a string value to match the default's type.
	 *
	 * @param string $raw_value Raw input.
	 * @param mixed  $type_ref  Default value for type detection.
	 * @return mixed
	 */
	private static function cast_value( string $raw_value, mixed $type_ref ): mixed {
		if ( is_bool( $type_ref ) ) {
			return in_array( strtolower( $raw_value ), [ 'true', '1', 'yes' ], true );
		}

		if ( is_int( $type_ref ) ) {
			return (int) $raw_value;
		}

		return $raw_value;
	}
}
