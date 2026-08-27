<?php
/**
 * Index of currently banned IP addresses.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A listable record of who is banned, why, and until when.
 *
 * The ban itself lives in the storage backend as a TTL'd key — that is what
 * the MU-plugin worker checks, and it stays the authority on whether an IP is
 * blocked. None of the three backends can enumerate keys portably (the file
 * backend hashes them, so an IP cannot even be recovered from a filename), so
 * this option is kept alongside purely so an administrator can answer "who is
 * banned right now, and why?" and lift one.
 *
 * Because the index and the storage can drift apart — a Redis flush, an APCu
 * restart, or a TTL expiring — a listing is always reconciled against the
 * storage rather than trusted on its own.
 */
final class BanList {

	/**
	 * Option holding the index. Never autoloaded.
	 */
	public const OPTION = 'lw_firewall_bans';

	/**
	 * Hard cap on tracked entries, so a large distributed attack cannot grow
	 * the option without bound. Oldest entries are dropped first.
	 */
	private const MAX_ENTRIES = 500;

	/**
	 * Record (or refresh) a ban.
	 *
	 * The expiry is rounded to the minute on purpose: `record()` runs on every
	 * request from an already-banned IP, and an unrounded timestamp would
	 * differ each time, making update_option() write to the database on every
	 * request of a flood. Rounded, the array is usually identical and
	 * update_option() returns without writing.
	 *
	 * @param string $ip       Banned IP.
	 * @param int    $duration Ban length in seconds.
	 * @param string $reason   Short machine-readable reason code.
	 * @return void
	 */
	public static function record( string $ip, int $duration, string $reason = '' ): void {
		if ( '' === $ip ) {
			return;
		}

		$entries = self::raw();
		$now     = time();

		$entries[ $ip ] = [
			'expires' => (int) ( ceil( ( $now + max( 0, $duration ) ) / MINUTE_IN_SECONDS ) * MINUTE_IN_SECONDS ),
			'reason'  => $reason,
			'time'    => isset( $entries[ $ip ]['time'] ) ? (int) $entries[ $ip ]['time'] : $now,
		];

		self::store( self::prune( $entries, $now ) );
	}

	/**
	 * Remove an entry from the index.
	 *
	 * @param string $ip Banned IP.
	 * @return void
	 */
	public static function forget( string $ip ): void {
		$entries = self::raw();

		if ( ! isset( $entries[ $ip ] ) ) {
			return;
		}

		unset( $entries[ $ip ] );

		self::store( $entries );
	}

	/**
	 * Every tracked ban, newest first, reconciled against the storage backend.
	 *
	 * @param \LightweightPlugins\Firewall\Storage\StorageInterface|null $storage Backend to verify against.
	 * @return array<int, array{ip: string, expires: int, reason: string, time: int, active: bool}>
	 */
	public static function all( $storage = null ): array {
		$now     = time();
		$entries = self::raw();
		$pruned  = self::prune( $entries, $now );

		if ( count( $pruned ) !== count( $entries ) ) {
			self::store( $pruned );
		}

		$rows = [];

		foreach ( $pruned as $ip => $entry ) {
			$rows[] = [
				'ip'      => (string) $ip,
				'expires' => (int) $entry['expires'],
				'reason'  => $entry['reason'],
				'time'    => $entry['time'],
				// A ban the storage no longer holds is not being enforced —
				// say so rather than listing a block that does not exist.
				'active'  => null === $storage || (bool) $storage->get( 'ban_' . $ip ),
			];
		}

		usort( $rows, static fn ( array $a, array $b ): int => $b['time'] <=> $a['time'] );

		return $rows;
	}

	/**
	 * Drop the whole index.
	 *
	 * @return void
	 */
	public static function clear(): void {
		delete_option( self::OPTION );
	}

	/**
	 * Remove expired entries and enforce the size cap.
	 *
	 * Pure function — the timestamp is passed in, so the pruning rule is unit
	 * testable without touching the clock.
	 *
	 * @param array<string, mixed> $entries Raw index.
	 * @param int                  $now     Current UNIX timestamp.
	 * @return array<string, array{expires: int, reason: string, time: int}>
	 */
	public static function prune( array $entries, int $now ): array {
		$clean = [];

		foreach ( $entries as $ip => $entry ) {
			if ( ! is_array( $entry ) || ! isset( $entry['expires'] ) ) {
				continue;
			}

			$expires = (int) $entry['expires'];

			if ( $expires <= $now ) {
				continue;
			}

			$clean[ (string) $ip ] = [
				'expires' => $expires,
				'reason'  => (string) ( $entry['reason'] ?? '' ),
				'time'    => (int) ( $entry['time'] ?? 0 ),
			];
		}

		if ( count( $clean ) > self::MAX_ENTRIES ) {
			uasort( $clean, static fn ( array $a, array $b ): int => $b['time'] <=> $a['time'] );
			$clean = array_slice( $clean, 0, self::MAX_ENTRIES, true );
		}

		return $clean;
	}

	/**
	 * Read the stored index without any processing.
	 *
	 * @return array<string, mixed>
	 */
	private static function raw(): array {
		$stored = get_option( self::OPTION, [] );

		return is_array( $stored ) ? $stored : [];
	}

	/**
	 * Persist the index.
	 *
	 * @param array<string, mixed> $entries Index to store.
	 * @return void
	 */
	private static function store( array $entries ): void {
		if ( empty( $entries ) ) {
			delete_option( self::OPTION );
			return;
		}

		update_option( self::OPTION, $entries, false );
	}
}
