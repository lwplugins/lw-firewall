<?php
/**
 * Firewall admin-alert CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\Alerts\AdminBaseline;
use LightweightPlugins\Firewall\Alerts\AdminDetector;
use LightweightPlugins\Firewall\Alerts\AdminMonitor;
use LightweightPlugins\Firewall\Alerts\AlertMailer;
use LightweightPlugins\Firewall\Alerts\BaselineDiff;
use LightweightPlugins\Firewall\Options;
use WP_CLI;
use WP_CLI\Utils;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage the new-administrator email alert.
 */
final class AlertsCommand {

	/**
	 * Show alert configuration and monitoring state.
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
	 *     $ wp lw-firewall alerts status
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 *
	 * @subcommand status
	 */
	public function status( array $args, array $assoc_args ): void {
		unset( $args );

		$next     = AdminMonitor::next_scan();
		$snapshot = AdminBaseline::last_updated();

		$items = [
			[
				'setting' => 'Alerts enabled',
				'value'   => Options::get( 'admin_alert_enabled' ) ? 'Yes' : 'No',
			],
			[
				'setting' => 'Scheduled scan',
				'value'   => Options::get( 'admin_alert_scan_enabled' ) ? 'Yes' : 'No',
			],
			[
				'setting' => 'Track identity changes',
				'value'   => Options::get( 'admin_alert_changes' ) ? 'Yes' : 'No',
			],
			[
				'setting' => 'Recipients',
				'value'   => implode( ', ', AlertMailer::recipients() ),
			],
			[
				'setting' => 'Administrators now',
				'value'   => (string) count( AdminDetector::current_admin_ids() ),
			],
			[
				'setting' => 'Snapshot taken',
				'value'   => $snapshot > 0 ? gmdate( 'Y-m-d H:i:s', $snapshot ) . ' UTC' : 'never',
			],
			[
				'setting' => 'Next scan',
				'value'   => $next > 0 ? gmdate( 'Y-m-d H:i:s', $next ) . ' UTC' : 'not scheduled',
			],
		];

		Utils\format_items(
			(string) Utils\get_flag_value( $assoc_args, 'format', 'table' ),
			$items,
			[ 'setting', 'value' ]
		);
	}

	/**
	 * Run the administrator reconciliation scan now.
	 *
	 * Compares the live administrator list against the stored snapshot and
	 * emails an alert for anything new. Use this to verify the feature, or
	 * from your own cron if WP-Cron is disabled.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall alerts scan
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments (unused).
	 *
	 * @subcommand scan
	 */
	public function scan( array $args, array $assoc_args ): void {
		unset( $args, $assoc_args );

		if ( ! Options::get( 'admin_alert_enabled' ) ) {
			WP_CLI::warning( 'Administrator alerts are disabled — nothing to do.' );
			return;
		}

		if ( ! AdminBaseline::is_seeded() ) {
			$ids = AdminBaseline::seed();
			WP_CLI::success( sprintf( 'Baseline seeded with %d administrator(s). No alerts sent.', count( $ids ) ) );
			return;
		}

		$result  = AdminMonitor::run_scan();
		$new     = $result['new'];
		$changes = $result['changes'];

		if ( empty( $new ) && empty( $changes ) ) {
			WP_CLI::success( 'No new or modified administrators found.' );
			return;
		}

		if ( ! empty( $new ) ) {
			WP_CLI::warning( sprintf( 'Found %d new administrator(s): %s', count( $new ), implode( ', ', array_map( 'strval', $new ) ) ) );
		}

		foreach ( $changes as $change ) {
			WP_CLI::warning(
				'pass' === $change['field']
					? sprintf( 'Administrator %d: password changed.', $change['id'] )
					: sprintf( 'Administrator %d: %s changed from "%s" to "%s".', $change['id'], $change['field'], $change['from'], $change['to'] )
			);
		}

		WP_CLI::log( 'An alert email was sent to: ' . implode( ', ', AlertMailer::recipients() ) );
	}

	/**
	 * Send a test alert to the configured recipients.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall alerts test
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments (unused).
	 *
	 * @subcommand test
	 */
	public function test( array $args, array $assoc_args ): void {
		unset( $args, $assoc_args );

		$to = AlertMailer::recipients();

		if ( empty( $to ) ) {
			WP_CLI::error( 'No valid recipient configured and the site admin email is unusable.' );
		}

		if ( ! AlertMailer::send_test() ) {
			WP_CLI::error( 'wp_mail() refused the message. Check your site mail configuration.' );
		}

		WP_CLI::success( 'Test alert handed to wp_mail() for: ' . implode( ', ', $to ) );
	}

	/**
	 * Show or rebuild the known-administrator snapshot.
	 *
	 * ## OPTIONS
	 *
	 * [--reset]
	 * : Re-take the snapshot from the current administrator list. Anything
	 * added before the reset is treated as known and will not alert.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall alerts baseline
	 *     $ wp lw-firewall alerts baseline --reset
	 *
	 * @param array<int, string>   $args       Positional arguments (unused).
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 *
	 * @subcommand baseline
	 */
	public function baseline( array $args, array $assoc_args ): void {
		unset( $args );

		if ( Utils\get_flag_value( $assoc_args, 'reset', false ) ) {
			$ids = AdminBaseline::seed();
			WP_CLI::success( sprintf( 'Snapshot rebuilt with %d administrator(s).', count( $ids ) ) );
			return;
		}

		if ( ! AdminBaseline::is_seeded() ) {
			WP_CLI::log( 'No snapshot yet — the first scan will take one silently.' );
			return;
		}

		$profiles = BaselineDiff::with_known_ids( AdminBaseline::get_profiles(), AdminBaseline::get_ids() );
		$items    = [];

		foreach ( $profiles as $user_id => $profile ) {
			$items[] = [
				'id'    => $user_id,
				'login' => $profile['login'] ?? '(not recorded)',
				'email' => $profile['email'] ?? '(not recorded)',
				'pass'  => isset( $profile['pass'] ) ? substr( $profile['pass'], 0, 12 ) . '…' : '(not recorded)',
			];
		}

		WP_CLI::log( sprintf( 'Known administrators (%d):', count( $items ) ) );
		Utils\format_items( 'table', $items, [ 'id', 'login', 'email', 'pass' ] );
		WP_CLI::log( 'Live administrator IDs: ' . implode( ', ', array_map( 'strval', AdminDetector::current_admin_ids() ) ) );
	}
}
