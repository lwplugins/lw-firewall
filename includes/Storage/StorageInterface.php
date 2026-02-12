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
	 * Check if storage backend is available.
	 *
	 * @return bool
	 */
	public static function is_available(): bool;
}
