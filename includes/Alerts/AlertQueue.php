<?php
/**
 * Alerts that could not be delivered yet.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Holds security notifications whose send failed, so the next scan retries them.
 *
 * The baseline snapshot is a deduplication record, not a delivery receipt.
 * Treating it as one meant an account was marked "reported" the moment it was
 * detected — so a single SMTP hiccup, hosting mail limit or misconfigured SMTP
 * plugin lost the notice that an administrator had appeared, permanently and
 * without anyone knowing.
 */
final class AlertQueue {

	/**
	 * Option holding undelivered alerts. Never autoloaded.
	 */
	public const OPTION = 'lw_firewall_alert_queue';

	/**
	 * Give up after this many scans, so a permanently broken mail setup cannot
	 * grow the option without bound. The admin transient still shows the
	 * failure.
	 */
	private const MAX_ATTEMPTS = 24;

	/**
	 * Read and clear the queue.
	 *
	 * @return array{new: array<int, int>, changes: array<int, array<string, mixed>>}
	 */
	public static function take(): array {
		$stored = get_option( self::OPTION, [] );

		delete_option( self::OPTION );

		if ( ! is_array( $stored ) ) {
			return self::empty_queue();
		}

		$attempts = (int) ( $stored['attempts'] ?? 0 );

		if ( $attempts >= self::MAX_ATTEMPTS ) {
			return self::empty_queue();
		}

		return [
			'new'     => AdminDetector::normalize( (array) ( $stored['new'] ?? [] ) ),
			'changes' => array_values( array_filter( (array) ( $stored['changes'] ?? [] ), 'is_array' ) ),
		];
	}

	/**
	 * Keep new-administrator alerts for the next attempt.
	 *
	 * @param array<int, int> $ids Administrator IDs.
	 * @return void
	 */
	public static function keep_new( array $ids ): void {
		self::store( [ 'new' => AdminDetector::normalize( $ids ) ] );
	}

	/**
	 * Keep identity-change alerts for the next attempt.
	 *
	 * @param array<int, array<string, mixed>> $changes Change records.
	 * @return void
	 */
	public static function keep_changes( array $changes ): void {
		self::store( [ 'changes' => array_values( $changes ) ] );
	}

	/**
	 * How many alerts are waiting to be delivered.
	 *
	 * @return int
	 */
	public static function pending(): int {
		$stored = get_option( self::OPTION, [] );

		if ( ! is_array( $stored ) ) {
			return 0;
		}

		return count( (array) ( $stored['new'] ?? [] ) ) + count( (array) ( $stored['changes'] ?? [] ) );
	}

	/**
	 * Merge one part into the stored queue and bump the attempt counter.
	 *
	 * @param array<string, mixed> $part Queue fragment.
	 * @return void
	 */
	private static function store( array $part ): void {
		$stored = get_option( self::OPTION, [] );
		$stored = is_array( $stored ) ? $stored : [];

		update_option(
			self::OPTION,
			array_merge(
				[
					'new'     => [],
					'changes' => [],
				],
				$stored,
				$part,
				[ 'attempts' => (int) ( $stored['attempts'] ?? 0 ) + 1 ]
			),
			false
		);
	}

	/**
	 * An empty queue.
	 *
	 * @return array{new: array<int, int>, changes: array<int, array<string, mixed>>}
	 */
	private static function empty_queue(): array {
		return [
			'new'     => [],
			'changes' => [],
		];
	}
}
