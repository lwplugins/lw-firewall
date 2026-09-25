<?php
/**
 * Index of currently locked usernames.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A listable record of locked usernames, the same way BanList records bans:
 * the lock itself is a TTL'd storage key, this option only lets an
 * administrator see and lift it. Capped, so a flood of made-up usernames
 * cannot grow it without bound.
 */
final class UserLockList {

	/**
	 * Option holding the index. Never autoloaded.
	 */
	public const OPTION = 'lw_firewall_user_locks';

	/**
	 * Hard cap on tracked entries; the oldest are dropped first.
	 */
	public const MAX_ENTRIES = 200;

	/**
	 * Longest username kept for display.
	 */
	private const MAX_DISPLAY = 60;

	/**
	 * Record (or refresh) a lock.
	 *
	 * @param string $key      UsernameKey::hash() of the login.
	 * @param string $user     Login as typed, for display.
	 * @param int    $duration Lock length in seconds.
	 * @return void
	 */
	public static function record( string $key, string $user, int $duration ): void {
		$entries = self::raw();
		$now     = time();

		$entries[ $key ] = [
			'user'    => substr( trim( $user ), 0, self::MAX_DISPLAY ),
			'expires' => (int) ( ceil( ( $now + max( 0, $duration ) ) / MINUTE_IN_SECONDS ) * MINUTE_IN_SECONDS ),
			'time'    => $now,
		];

		self::store( self::prune( $entries, $now ) );
	}

	/**
	 * Remove an entry.
	 *
	 * @param string $key Lock key.
	 * @return void
	 */
	public static function forget( string $key ): void {
		$entries = self::raw();

		if ( isset( $entries[ $key ] ) ) {
			unset( $entries[ $key ] );
			self::store( $entries );
		}
	}

	/**
	 * Every tracked lock, newest first, reconciled against the storage.
	 *
	 * @param StorageInterface $storage Backend holding the locks.
	 * @return array<int, array{key: string, user: string, expires: int, time: int, active: bool}>
	 */
	public static function all( StorageInterface $storage ): array {
		$rows = [];

		foreach ( self::prune( self::raw(), time() ) as $key => $entry ) {
			$rows[] = [
				'key'     => (string) $key,
				'user'    => $entry['user'],
				'expires' => $entry['expires'],
				'time'    => $entry['time'],
				'active'  => (bool) $storage->get( UserLockout::LOCK_PREFIX . $key ),
			];
		}

		usort( $rows, static fn ( array $a, array $b ): int => $b['time'] <=> $a['time'] );

		return $rows;
	}

	/**
	 * Lock key => username as typed, for every stored entry (no pruning).
	 *
	 * @return array<string, string>
	 */
	public static function names(): array {
		$names = [];

		foreach ( self::raw() as $key => $entry ) {
			$names[ (string) $key ] = is_array( $entry ) ? (string) ( $entry['user'] ?? '' ) : '';
		}

		return $names;
	}

	/**
	 * The keys of the index.
	 *
	 * @return array<int, string>
	 */
	public static function keys(): array {
		return array_map( 'strval', array_keys( self::raw() ) );
	}

	/**
	 * Remove expired entries and enforce the cap. Pure.
	 *
	 * @param array<string|int, mixed> $entries Raw index.
	 * @param int                      $now     Current UNIX timestamp.
	 * @return array<string, array{user: string, expires: int, time: int}>
	 */
	public static function prune( array $entries, int $now ): array {
		$clean = [];

		foreach ( $entries as $key => $entry ) {
			if ( ! is_array( $entry ) || (int) ( $entry['expires'] ?? 0 ) <= $now ) {
				continue;
			}

			$clean[ (string) $key ] = [
				'user'    => (string) ( $entry['user'] ?? '' ),
				'expires' => (int) $entry['expires'],
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
	 * The stored index.
	 *
	 * @return array<string|int, mixed>
	 */
	private static function raw(): array {
		$stored = get_option( self::OPTION, [] );

		return is_array( $stored ) ? $stored : [];
	}

	/**
	 * Persist the index.
	 *
	 * @param array<string, mixed> $entries Index.
	 * @return void
	 */
	private static function store( array $entries ): void {
		if ( [] === $entries ) {
			delete_option( self::OPTION );
			return;
		}

		update_option( self::OPTION, $entries, false );
	}
}
