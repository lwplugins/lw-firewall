<?php
/**
 * Firewall config CLI command — read / write whole values.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\CLI\Support\ConfigOpsTrait;
use LightweightPlugins\Firewall\CLI\Support\ValueCaster;
use LightweightPlugins\Firewall\Options;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage firewall configuration values.
 */
final class ConfigCommand {

	use ConfigOpsTrait;

	/**
	 * List all configuration values.
	 *
	 * `table` / `csv` render arrays as `[a, b, c]` so lists are visually
	 * distinct from strings. `json` / `yaml` preserve the original type.
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
	 *     $ wp lw-firewall config list --format=json
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 *
	 * @subcommand list
	 */
	public function list_config( array $args, array $assoc_args ): void {
		unset( $args );

		$format         = (string) Utils\get_flag_value( $assoc_args, 'format', 'table' );
		$preserve_types = in_array( $format, [ 'json', 'yaml' ], true );
		$items          = [];

		foreach ( Options::get_all() as $key => $value ) {
			$items[] = [
				'key'   => $key,
				'value' => $preserve_types ? $value : ValueCaster::stringify( $value ),
			];
		}

		Utils\format_items( $format, $items, [ 'key', 'value' ] );
	}

	/**
	 * Get a single configuration value.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The setting key.
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: var_export
	 * options:
	 *   - var_export
	 *   - json
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall config get filter_params --format=json
	 *
	 * @param array<int, string>   $args       Positional arguments.
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 */
	public function get( array $args, array $assoc_args ): void {
		[ $key ] = $args;
		self::assert_known_key( $key );

		$value  = Options::get( $key );
		$format = (string) Utils\get_flag_value( $assoc_args, 'format', 'var_export' );

		if ( in_array( $format, [ 'json', 'yaml' ], true ) ) {
			WP_CLI::print_value( $value, [ 'format' => $format ] );
			return;
		}

		WP_CLI::log( ValueCaster::stringify( $value ) );
	}

	/**
	 * Set a configuration value.
	 *
	 * Lists (filter_params, blocked_bots, ip_whitelist, ip_blacklist,
	 * blocked_countries) accept comma- or newline-separated entries.
	 * Booleans accept true/false/1/0/yes/no/on/off.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The setting key.
	 *
	 * <value>
	 * : The new value.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall config set rate_limit 50
	 *     $ wp lw-firewall config set filter_params "filter_|30,add-to-cart|10"
	 *     $ wp lw-firewall config set blocked_countries "CN,RU,KP"
	 *
	 * @param array<int, string>   $args       Positional arguments.
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 */
	public function set( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		[ $key, $raw_value ] = $args;

		$defaults = Options::get_defaults();
		self::assert_known_key( $key, $defaults );

		$value           = ValueCaster::cast( (string) $raw_value, $defaults[ $key ] );
		$current         = Options::get_all();
		$current[ $key ] = $value;

		if ( ! Options::save( $current ) ) {
			WP_CLI::error( "Failed to update '{$key}'." );
		}

		WP_CLI::success( sprintf( "Set '%s' to %s.", $key, ValueCaster::stringify( $value ) ) );
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
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 */
	public function reset( array $args, array $assoc_args ): void {
		unset( $args );
		WP_CLI::confirm( 'Reset all firewall settings to defaults?', $assoc_args );

		if ( ! Options::save( Options::get_defaults() ) ) {
			WP_CLI::error( 'Failed to reset settings.' );
		}

		WP_CLI::success( 'All settings reset to defaults.' );
	}
}
