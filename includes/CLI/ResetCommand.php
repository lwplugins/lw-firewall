<?php
/**
 * Password-reset flood protection CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\Alerts\AlertMailer;
use LightweightPlugins\Firewall\Options;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage password-reset flood protection.
 */
final class ResetCommand {

	/**
	 * Boolean settings this command can flip, in display order.
	 *
	 * @var array<string, string>
	 */
	private const TOGGLES = [
		'reset_protect_enabled' => 'Reset protection',
		'reset_proof_enabled'   => 'Proof of render',
		'reset_single_use'      => 'Single-use token',
		'reset_auto_ban'        => 'Auto-ban',
		'reset_alert_enabled'   => 'Email alert',
		'reset_block_admins'    => 'Block admin resets',
	];

	/**
	 * Numeric limits this command reports, in display order.
	 *
	 * @var array<string, string>
	 */
	private const LIMITS = [
		'reset_ip_max'        => 'Requests per IP',
		'reset_ip_window'     => 'Per-IP window (s)',
		'reset_user_max'      => 'Requests per account',
		'reset_user_window'   => 'Per-account window (s)',
		'reset_global_max'    => 'Site-wide hourly cap',
		'reset_min_fill_time' => 'Minimum fill time (s)',
		'reset_token_max_age' => 'Token lifetime (s)',
		'reset_ban_duration'  => 'Ban duration (s)',
	];

	/**
	 * Show password-reset protection settings.
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
	 *     $ wp lw-firewall reset status
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 *
	 * @subcommand status
	 */
	public function status( array $args, array $assoc_args ): void {
		unset( $args );

		$items = [];

		foreach ( self::TOGGLES as $key => $label ) {
			$items[] = [
				'setting' => $label,
				'value'   => Options::get( $key ) ? 'Yes' : 'No',
				'key'     => $key,
			];
		}

		foreach ( self::LIMITS as $key => $label ) {
			$value = (int) Options::get( $key );

			$items[] = [
				'setting' => $label,
				'value'   => 0 === $value ? 'disabled' : (string) $value,
				'key'     => $key,
			];
		}

		$items[] = [
			'setting' => 'Alert recipients',
			'value'   => implode( ', ', AlertMailer::recipients() ),
			'key'     => 'admin_alert_email',
		];

		Utils\format_items(
			(string) Utils\get_flag_value( $assoc_args, 'format', 'table' ),
			$items,
			[ 'setting', 'value', 'key' ]
		);
	}

	/**
	 * Turn password-reset flood protection on.
	 *
	 * ## OPTIONS
	 *
	 * [--proof]
	 * : Also require the proof-of-render token on the wp-login form.
	 *
	 * [--auto-ban]
	 * : Also ban IPs that trip the per-IP limit or fail the token check.
	 *
	 * [--alert]
	 * : Also email the Alerts-tab recipients when a limit is reached.
	 *
	 * [--block-admins]
	 * : Also refuse password resets for administrator accounts entirely.
	 * Recovery then needs WP-CLI or another administrator.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall reset on
	 *     $ wp lw-firewall reset on --proof --auto-ban --alert
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 *
	 * @subcommand on
	 */
	public function on( array $args, array $assoc_args ): void {
		unset( $args );

		$values = [ 'reset_protect_enabled' => true ];

		foreach ( self::flag_map() as $flag => $key ) {
			if ( Utils\get_flag_value( $assoc_args, $flag, false ) ) {
				$values[ $key ] = true;
			}
		}

		Options::save( $values );

		WP_CLI::success( 'Password reset protection enabled: ' . implode( ', ', array_keys( $values ) ) . '.' );
		WP_CLI::log( 'Run `wp lw-firewall reset status` to see the active limits.' );
	}

	/**
	 * Turn password-reset flood protection off.
	 *
	 * Leaves the individual limits and hardening settings as they are, so
	 * turning it back on restores the same configuration.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall reset off
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments (unused).
	 *
	 * @subcommand off
	 */
	public function off( array $args, array $assoc_args ): void {
		unset( $args, $assoc_args );

		Options::save( [ 'reset_protect_enabled' => false ] );

		WP_CLI::success( 'Password reset protection disabled.' );
	}

	/**
	 * Map CLI flags to the option they enable.
	 *
	 * @return array<string, string>
	 */
	private static function flag_map(): array {
		return [
			'proof'        => 'reset_proof_enabled',
			'auto-ban'     => 'reset_auto_ban',
			'alert'        => 'reset_alert_enabled',
			'block-admins' => 'reset_block_admins',
		];
	}
}
