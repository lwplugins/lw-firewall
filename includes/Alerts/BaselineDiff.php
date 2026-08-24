<?php
/**
 * Pure comparison of administrator snapshots.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The detection core: what changed between two administrator snapshots.
 *
 * Every method here is pure — no WordPress calls, no database, no options —
 * so the logic that decides whether to raise a security alert is fully unit
 * testable. Storage lives in AdminBaseline, reading the live site lives in
 * AdminDetector; this class only compares.
 */
final class BaselineDiff {

	/**
	 * Administrator IDs present now but absent from the baseline.
	 *
	 * @param array<int|string, mixed> $baseline Previously known IDs.
	 * @param array<int|string, mixed> $current  IDs observed right now.
	 * @return array<int, int> Newly appeared administrator IDs.
	 */
	public static function ids( array $baseline, array $current ): array {
		$known = AdminDetector::normalize( $baseline );
		$now   = AdminDetector::normalize( $current );

		return array_values( array_diff( $now, $known ) );
	}

	/**
	 * Identity changes on administrators the baseline already knew about.
	 *
	 * Accounts missing from either side are skipped: a newly appeared account
	 * is already reported by ids(), and an account whose stored fingerprint
	 * predates this feature has nothing to compare against — it is filled in
	 * silently instead of raising a phantom alert.
	 *
	 * @param array<int|string, mixed> $baseline Stored fingerprints keyed by user ID.
	 * @param array<int|string, mixed> $current  Fingerprints observed right now.
	 * @return array<int, array{id: int, field: string, from: string, to: string}>
	 */
	public static function profiles( array $baseline, array $current ): array {
		$old     = self::normalize_profiles( $baseline );
		$new     = self::normalize_profiles( $current );
		$changes = [];

		foreach ( $new as $user_id => $profile ) {
			if ( ! isset( $old[ $user_id ] ) ) {
				continue;
			}

			foreach ( AdminDetector::PROFILE_FIELDS as $field ) {
				if ( ! isset( $old[ $user_id ][ $field ], $profile[ $field ] ) ) {
					continue;
				}

				if ( $old[ $user_id ][ $field ] === $profile[ $field ] ) {
					continue;
				}

				$changes[] = [
					'id'    => $user_id,
					'field' => $field,
					'from'  => $old[ $user_id ][ $field ],
					'to'    => $profile[ $field ],
				];
			}
		}

		return $changes;
	}

	/**
	 * Ensure every known administrator ID has an entry in the fingerprint map.
	 *
	 * The snapshot derives its ID list from the fingerprint map, so writing a
	 * single account back must not drop the others. This matters most on a
	 * snapshot written before identity tracking existed: it holds IDs but no
	 * fingerprints, and without this the first hook event would shrink the
	 * baseline to one account and the next scan would report every remaining
	 * administrator as brand new.
	 *
	 * Placeholder entries are empty, which diff_profiles() treats as "nothing
	 * to compare" — they get filled in silently, never reported.
	 *
	 * @param array<int|string, mixed> $profiles  Fingerprint map.
	 * @param array<int|string, mixed> $known_ids IDs the snapshot already had.
	 * @return array<int, array<string, string>>
	 */
	public static function with_known_ids( array $profiles, array $known_ids ): array {
		$clean = self::normalize_profiles( $profiles );

		foreach ( AdminDetector::normalize( $known_ids ) as $user_id ) {
			if ( ! isset( $clean[ $user_id ] ) ) {
				$clean[ $user_id ] = [];
			}
		}

		ksort( $clean );

		return $clean;
	}

	/**
	 * Coerce a stored or freshly built fingerprint map into a clean shape.
	 *
	 * Option values come back from the database with array keys as strings and
	 * may have been written by an older version, so nothing about the shape is
	 * assumed.
	 *
	 * @param array<int|string, mixed> $profiles Raw fingerprint map.
	 * @return array<int, array<string, string>>
	 */
	public static function normalize_profiles( array $profiles ): array {
		$clean = [];

		foreach ( $profiles as $user_id => $profile ) {
			$user_id = (int) $user_id;

			if ( $user_id <= 0 || ! is_array( $profile ) ) {
				continue;
			}

			$entry = [];

			foreach ( AdminDetector::PROFILE_FIELDS as $field ) {
				if ( isset( $profile[ $field ] ) && is_scalar( $profile[ $field ] ) ) {
					$entry[ $field ] = (string) $profile[ $field ];
				}
			}

			$clean[ $user_id ] = $entry;
		}

		ksort( $clean );

		return $clean;
	}
}
