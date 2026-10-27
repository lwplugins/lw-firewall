<?php
/**
 * Atomic, database-backed attempt counters of the second-factor step.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use wpdb;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The two brute-force bounds (answers per pending token, failures per account)
 * must hold on every install, so they do not use the firewall's request
 * storage (its backends fall back to "1" when Redis is down or the cache
 * directory is unwritable, and APCu counts per server). Each counter is one
 * usermeta row of the account, read and written only with prepared $wpdb
 * statements, never through the meta API or the object cache.
 *
 * The value is one integer: window start (Unix time) × 1000 + count. One
 * UPDATE either starts a new window (the old one expired) or adds one, so
 * parallel requests cannot lose an increment; a count stops at 999.
 *
 * Fail closed: every database error reads as "exhausted".
 */
final class AttemptCounter {

	/**
	 * What a counter reads as after a database error.
	 */
	public const EXHAUSTED = PHP_INT_MAX;

	private const SCALE = 1000;

	private const CAP = 999;

	/**
	 * Constructor.
	 *
	 * @param \Closure|null $clock Returns the current Unix time (tests); null = time().
	 * @param wpdb|null     $db    Database (tests); null = the global $wpdb.
	 */
	public function __construct( private readonly ?\Closure $clock = null, private readonly ?wpdb $db = null ) {}

	/**
	 * Add one, starting a new window when the stored one is older than $window.
	 *
	 * @param int    $user_id Account.
	 * @param string $key     Meta key.
	 * @param int    $window  Window length in seconds.
	 * @return int The count after this attempt (EXHAUSTED on a database error).
	 */
	public function increment( int $user_id, string $key, int $window ): int {
		$db  = $this->db();
		$now = $this->now();
		if ( ! $this->ensure_row( $user_id, $key ) ) {
			return self::EXHAUSTED;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic counter; must bypass the meta cache.
		$updated = $db->query(
			$db->prepare(
				"UPDATE {$db->usermeta} SET meta_value = CASE WHEN CAST(meta_value AS SIGNED) < %d THEN %d WHEN CAST(meta_value AS SIGNED) %% 1000 < %d THEN CAST(meta_value AS SIGNED) + 1 ELSE CAST(meta_value AS SIGNED) END WHERE user_id = %d AND meta_key = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Core table name from $wpdb.
				( $now - $window ) * self::SCALE,
				$now * self::SCALE + 1,
				self::CAP,
				$user_id,
				$key
			)
		);
		$this->flush( $user_id );
		if ( false === $updated || 0 === $updated ) {
			return self::EXHAUSTED;
		}

		return $this->count( $user_id, $key, $window );
	}

	/**
	 * The count of the current window (0 when none or expired).
	 *
	 * @param int    $user_id Account.
	 * @param string $key     Meta key.
	 * @param int    $window  Window length in seconds.
	 * @return int EXHAUSTED on a database error.
	 */
	public function count( int $user_id, string $key, int $window ): int {
		$db = $this->db();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Counter read must bypass the meta cache.
		$value = $db->get_var(
			$db->prepare(
				"SELECT MAX(CAST(meta_value AS SIGNED)) FROM {$db->usermeta} WHERE user_id = %d AND meta_key = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Core table name from $wpdb.
				$user_id,
				$key
			)
		);
		if ( '' !== $db->last_error ) {
			return self::EXHAUSTED;
		}
		if ( null === $value ) {
			return 0;
		}

		$value = (int) $value;

		return $value < ( $this->now() - $window ) * self::SCALE ? 0 : $value % self::SCALE;
	}

	/**
	 * Start a fresh window that already holds $count (e.g. a block begins now).
	 *
	 * One UPDATE on the existing rows: the counter never disappears, so a
	 * failure leaves the previous (already high) count in place.
	 *
	 * @param int    $user_id Account.
	 * @param string $key     Meta key.
	 * @param int    $count   Count to hold.
	 * @return bool False on a database error (the old value then stays).
	 */
	public function hold( int $user_id, string $key, int $count ): bool {
		if ( ! $this->ensure_row( $user_id, $key ) ) {
			return false;
		}

		$db = $this->db();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic counter; must bypass the meta cache.
		$updated = $db->query(
			$db->prepare(
				"UPDATE {$db->usermeta} SET meta_value = %s WHERE user_id = %d AND meta_key = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Core table name from $wpdb.
				(string) ( $this->now() * self::SCALE + min( self::CAP, max( 0, $count ) ) ),
				$user_id,
				$key
			)
		);
		$this->flush( $user_id );

		return false !== $updated && 0 !== $updated;
	}

	/**
	 * Remove a counter.
	 *
	 * @param int    $user_id Account.
	 * @param string $key     Meta key.
	 */
	public function delete( int $user_id, string $key ): bool {
		$db = $this->db();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Counter row, meta cache flushed below.
		$done = $db->query( $db->prepare( "DELETE FROM {$db->usermeta} WHERE user_id = %d AND meta_key = %s", $user_id, $key ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Core table name from $wpdb.
		$this->flush( $user_id );

		return false !== $done;
	}

	/**
	 * Remove an account's counters under a key prefix whose window ended.
	 *
	 * @param int    $user_id Account.
	 * @param string $prefix  Meta key prefix.
	 * @param int    $window  Window length in seconds.
	 */
	public function purge( int $user_id, string $prefix, int $window ): void {
		$db = $this->db();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Housekeeping of counter rows, meta cache flushed below.
		$db->query(
			$db->prepare(
				"DELETE FROM {$db->usermeta} WHERE user_id = %d AND meta_key LIKE %s AND CAST(meta_value AS SIGNED) < %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Core table name from $wpdb.
				$user_id,
				$db->esc_like( $prefix ) . '%',
				( $this->now() - $window ) * self::SCALE
			)
		);
		$this->flush( $user_id );
	}

	/**
	 * Create the row when missing (a parallel duplicate is harmless: every
	 * row is updated together and the highest is read).
	 *
	 * @param int    $user_id Account.
	 * @param string $key     Meta key.
	 */
	private function ensure_row( int $user_id, string $key ): bool {
		$db = $this->db();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Counter row lookup, must bypass the meta cache.
		$rows = $db->get_var( $db->prepare( "SELECT COUNT(*) FROM {$db->usermeta} WHERE user_id = %d AND meta_key = %s", $user_id, $key ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Core table name from $wpdb.
		if ( '' !== $db->last_error || null === $rows ) {
			return false;
		}

		return (int) $rows > 0 || $this->insert( $user_id, $key, $this->now() * self::SCALE );
	}

	/**
	 * Insert a counter row.
	 *
	 * @param int    $user_id Account.
	 * @param string $key     Meta key.
	 * @param int    $value   Encoded value.
	 */
	private function insert( int $user_id, string $key, int $value ): bool {
		$db = $this->db();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Counter row, meta cache flushed below.
		$done = $db->query( $db->prepare( "INSERT INTO {$db->usermeta} (user_id, meta_key, meta_value) VALUES (%d, %s, %s)", $user_id, $key, (string) $value ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Core table name from $wpdb.
		$this->flush( $user_id );

		return false !== $done;
	}

	/**
	 * Drop the account's cached meta so no reader sees a stale row.
	 *
	 * @param int $user_id Account.
	 */
	private function flush( int $user_id ): void {
		wp_cache_delete( $user_id, 'user_meta' );
	}

	/**
	 * Database.
	 */
	private function db(): wpdb {
		global $wpdb;

		return $this->db ?? $wpdb;
	}

	/**
	 * Current Unix time.
	 */
	private function now(): int {
		return null === $this->clock ? time() : (int) ( $this->clock )();
	}
}
