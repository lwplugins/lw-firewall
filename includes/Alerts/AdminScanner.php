<?php
/**
 * Administrator reconciliation scan.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Diffs the live administrator list against the stored baseline.
 *
 * This is the only detection path that sees changes WordPress never announced:
 * a direct database write, code bypassing the core user API, or anything that
 * happened while the plugin was inactive.
 */
final class AdminScanner {

	/**
	 * Run the reconciliation and alert on whatever it finds.
	 *
	 * @return array{new: array<int, int>, changes: array<int, array{id: int, field: string, from: string, to: string}>}
	 */
	public static function run(): array {
		$empty = [
			'new'     => [],
			'changes' => [],
		];

		if ( empty( Options::get( 'admin_alert_enabled' ) ) ) {
			return $empty;
		}

		$current = AdminDetector::current_admins();

		// No baseline yet: record the current state silently. Alerting before
		// the first snapshot would mail about every administrator the site
		// already had.
		if ( ! AdminBaseline::is_seeded() ) {
			AdminBaseline::store( $current );
			return $empty;
		}

		$new     = BaselineDiff::ids( AdminBaseline::get_ids(), array_keys( $current ) );
		$changes = self::detect_changes( $current );

		AdminBaseline::store( $current );

		// A send that fails is retried on the next scan. The baseline is the
		// deduplication record, not a delivery receipt — treating it as one
		// meant a single SMTP hiccup lost the notification that an
		// administrator account had appeared, permanently and silently.
		$pending = AlertQueue::take();

		if ( ! empty( $new ) ) {
			$pending['new'] = array_values( array_unique( array_merge( $pending['new'], $new ) ) );
		}

		if ( ! empty( $changes ) ) {
			$pending['changes'] = array_merge( $pending['changes'], $changes );
		}

		if ( ! empty( $pending['new'] ) && ! AlertMailer::notify( $pending['new'], 'scan' ) ) {
			AlertQueue::keep_new( $pending['new'] );
		}

		if ( ! empty( $pending['changes'] ) && ! AlertMailer::notify_changes( $pending['changes'], 'scan' ) ) {
			AlertQueue::keep_changes( $pending['changes'] );
		}

		return [
			'new'     => $new,
			'changes' => $changes,
		];
	}

	/**
	 * Identity changes on administrators the baseline already knew about.
	 *
	 * @param array<int, array<string, string>> $current Live fingerprints.
	 * @return array<int, array{id: int, field: string, from: string, to: string}>
	 */
	private static function detect_changes( array $current ): array {
		if ( empty( Options::get( 'admin_alert_changes' ) ) ) {
			return [];
		}

		return BaselineDiff::profiles( AdminBaseline::get_profiles(), $current );
	}
}
