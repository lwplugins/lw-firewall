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
	 * The flags say what happened, so a caller can report it honestly:
	 * `disabled` (alerts off, nothing scanned), `seeded` (first snapshot
	 * taken silently), `sent` (an alert mail went out) and `queued` (a mail
	 * failed and was kept for the next scan).
	 *
	 * @return array{new: array<int, int>, changes: array<int, array{id: int, field: string, from: string, to: string}>, disabled: bool, seeded: bool, sent: bool, queued: bool}
	 */
	public static function run(): array {
		$empty = [
			'new'      => [],
			'changes'  => [],
			'disabled' => false,
			'seeded'   => false,
			'sent'     => false,
			'queued'   => false,
		];

		if ( empty( Options::get( 'admin_alert_enabled' ) ) ) {
			return array_merge( $empty, [ 'disabled' => true ] );
		}

		$current = AdminDetector::current_admins();

		// No baseline yet: record the current state silently. Alerting before
		// the first snapshot would mail about every administrator the site
		// already had.
		if ( ! AdminBaseline::is_seeded() ) {
			AdminBaseline::store( $current );
			return array_merge( $empty, [ 'seeded' => true ] );
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

		$sent   = false;
		$queued = false;

		if ( ! empty( $pending['new'] ) ) {
			if ( AlertMailer::notify( $pending['new'], 'scan' ) ) {
				$sent = true;
			} else {
				AlertQueue::keep_new( $pending['new'] );
				$queued = true;
			}
		}

		if ( ! empty( $pending['changes'] ) ) {
			if ( AlertMailer::notify_changes( $pending['changes'], 'scan' ) ) {
				$sent = true;
			} else {
				AlertQueue::keep_changes( $pending['changes'] );
				$queued = true;
			}
		}

		return array_merge(
			$empty,
			[
				'new'     => $new,
				'changes' => $changes,
				'sent'    => $sent,
				'queued'  => $queued,
			]
		);
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
