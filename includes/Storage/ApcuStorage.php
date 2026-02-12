<?php
/**
 * APCu storage backend.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rate-limit counter storage using APCu shared memory.
 */
final class ApcuStorage implements StorageInterface {

	/**
	 * Key prefix for APCu entries.
	 *
	 * @var string
	 */
	private string $prefix = 'lw_fw_';

	/**
	 * Get a value by key.
	 *
	 * @param string $key Cache key.
	 * @return mixed
	 */
	public function get( string $key ): mixed {
		$success = false;
		$value   = apcu_fetch( $this->prefix . $key, $success );

		return $success ? $value : null;
	}

	/**
	 * Set a value with TTL in seconds.
	 *
	 * @param string $key   Cache key.
	 * @param mixed  $value Value to store.
	 * @param int    $ttl   Time-to-live in seconds.
	 * @return bool
	 */
	public function set( string $key, mixed $value, int $ttl ): bool {
		return apcu_store( $this->prefix . $key, $value, $ttl );
	}

	/**
	 * Increment a counter. Returns the new value.
	 *
	 * @param string $key Cache key.
	 * @param int    $ttl Time-to-live in seconds.
	 * @return int
	 */
	public function increment( string $key, int $ttl ): int {
		$full_key = $this->prefix . $key;

		// Try to increment existing value.
		$success = false;
		$result  = apcu_inc( $full_key, 1, $success );

		if ( $success && false !== $result ) {
			return (int) $result;
		}

		// Key doesn't exist — create it.
		apcu_store( $full_key, 1, $ttl );

		return 1;
	}

	/**
	 * Check if APCu is available.
	 *
	 * @return bool
	 */
	public static function is_available(): bool {
		return function_exists( 'apcu_store' ) && apcu_enabled();
	}
}
