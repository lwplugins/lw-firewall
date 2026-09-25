<?php
/**
 * Storage backend interface.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Contract for rate-limit counter storage backends.
 */
interface StorageInterface {

	/**
	 * Get a value by key.
	 *
	 * Impure: the value changes with every set/increment/delete, whoever
	 * makes them, so two reads of the same key may differ.
	 *
	 * @phpstan-impure
	 *
	 * @param string $key Cache key.
	 * @return mixed
	 */
	public function get( string $key ): mixed;

	/**
	 * Set a value with TTL in seconds.
	 *
	 * @param string $key   Cache key.
	 * @param mixed  $value Value to store.
	 * @param int    $ttl   Time-to-live in seconds.
	 * @return bool
	 */
	public function set( string $key, mixed $value, int $ttl ): bool;

	/**
	 * Increment a counter. Returns the new value.
	 *
	 * @param string $key Cache key.
	 * @param int    $ttl Time-to-live in seconds.
	 * @return int
	 */
	public function increment( string $key, int $ttl ): int;

	/**
	 * Delete a key. Returns true when the key is gone afterwards.
	 *
	 * Used to lift a ban and clear the counters behind it, so the operation
	 * must report success when the key never existed — an already-absent key
	 * is the state the caller asked for.
	 *
	 * @param string $key Cache key.
	 * @return bool
	 */
	public function delete( string $key ): bool;

	/**
	 * Check if storage backend is available.
	 *
	 * @return bool
	 */
	public static function is_available(): bool;
}
