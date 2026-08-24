<?php
/**
 * Known-administrator baseline snapshot.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Persists who the site's administrators are and what they look like.
 *
 * Two things are recorded per snapshot:
 *
 * - the set of administrator user IDs, which detects accounts that *appear*;
 * - an identity fingerprint per account (username, email, password digest),
 *   which detects an existing administrator being *taken over* — the ID never
 *   changes when an attacker rewrites the email address to seize the password
 *   reset flow, so the ID diff alone would never see it.
 *
 * This is also the single source of truth for de-duplication: both the hook
 * path (a change WordPress told us about) and the scan path (a reconciliation
 * against the database) write here, so one event produces one alert.
 *
 * The record is intentionally *replaced* on every scan rather than appended
 * to — a demoted account leaves the baseline, so re-promoting it later alerts
 * again, which is the behaviour you want from a security monitor.
 */
final class AdminBaseline {

	/**
	 * Option holding the snapshot. Never autoloaded.
	 */
	public const OPTION = 'lw_firewall_admin_baseline';

	/**
	 * Read the stored snapshot record.
	 *
	 * @return array{ids: array<int, int>, profiles: array<int, array<string, string>>, time: int}|null
	 *         Null when never seeded.
	 */
	public static function get_record(): ?array {
		$stored = get_option( self::OPTION, null );

		if ( ! is_array( $stored ) || ! isset( $stored['ids'] ) || ! is_array( $stored['ids'] ) ) {
			return null;
		}

		$profiles = isset( $stored['profiles'] ) && is_array( $stored['profiles'] )
			? BaselineDiff::normalize_profiles( $stored['profiles'] )
			: [];

		return [
			'ids'      => AdminDetector::normalize( $stored['ids'] ),
			'profiles' => $profiles,
			'time'     => (int) ( $stored['time'] ?? 0 ),
		];
	}

	/**
	 * The administrator IDs recorded in the snapshot.
	 *
	 * @return array<int, int>
	 */
	public static function get_ids(): array {
		$record = self::get_record();

		return null === $record ? [] : $record['ids'];
	}

	/**
	 * The identity fingerprints recorded in the snapshot.
	 *
	 * @return array<int, array<string, string>>
	 */
	public static function get_profiles(): array {
		$record = self::get_record();

		return null === $record ? [] : $record['profiles'];
	}

	/**
	 * Whether a baseline has ever been taken.
	 *
	 * Alerting must never fire before the first snapshot exists, otherwise
	 * every site upgrading into this feature would be mailed about all of its
	 * pre-existing administrators.
	 *
	 * @return bool
	 */
	public static function is_seeded(): bool {
		return null !== self::get_record();
	}

	/**
	 * Replace the snapshot.
	 *
	 * @param array<int, array<string, string>> $admins Fingerprints keyed by user ID.
	 * @return void
	 */
	public static function store( array $admins ): void {
		$profiles = BaselineDiff::normalize_profiles( $admins );

		update_option(
			self::OPTION,
			[
				'ids'      => AdminDetector::normalize( array_keys( $profiles ) ),
				'profiles' => $profiles,
				'time'     => time(),
			],
			false
		);
	}

	/**
	 * Take a silent snapshot of the current administrators.
	 *
	 * @return array<int, int> The IDs that were recorded.
	 */
	public static function seed(): array {
		$admins = AdminDetector::current_admins();
		self::store( $admins );

		return AdminDetector::normalize( array_keys( $admins ) );
	}

	/**
	 * Whether the snapshot already contains this user.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function knows( int $user_id ): bool {
		return in_array( $user_id, self::get_ids(), true );
	}

	/**
	 * Record a single user's current state in the snapshot.
	 *
	 * Used by the hook path so an account that WordPress just told us about
	 * is never reported a second time by the scan.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public static function remember( int $user_id ): void {
		$profile = AdminDetector::profile( $user_id );

		if ( null === $profile ) {
			return;
		}

		// Rebuild from the full known-ID list, not just the fingerprint map:
		// store() derives the ID list from the map, so a snapshot that predates
		// identity tracking would otherwise shrink to this one account.
		$profiles = BaselineDiff::with_known_ids( self::get_profiles(), self::get_ids() );

		$profiles[ $user_id ] = $profile;

		self::store( $profiles );
	}

	/**
	 * Timestamp of the last snapshot write (0 when never seeded).
	 *
	 * @return int
	 */
	public static function last_updated(): int {
		$record = self::get_record();

		return null === $record ? 0 : $record['time'];
	}

	/**
	 * Drop the snapshot entirely; the next scan re-seeds silently.
	 *
	 * @return void
	 */
	public static function reset(): void {
		delete_option( self::OPTION );
	}
}
