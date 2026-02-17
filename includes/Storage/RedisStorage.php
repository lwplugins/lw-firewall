<?php
/**
 * Redis storage backend.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rate-limit counter storage using Redis.
 */
final class RedisStorage implements StorageInterface {

	/**
	 * Key prefix for Redis entries.
	 *
	 * @var string
	 */
	private string $prefix = 'lw_fw_';

	/**
	 * Redis client instance.
	 *
	 * @var \Redis
	 */
	private \Redis $redis;

	/**
	 * Connect to Redis on construction.
	 *
	 * @param string $host Redis host.
	 * @param int    $port Redis port.
	 */
	public function __construct( string $host = '127.0.0.1', int $port = 6379 ) {
		$this->redis = new \Redis();
		$this->redis->connect( $host, $port, 1.0 ); // 1s timeout.
	}

	/**
	 * Get a value by key.
	 *
	 * @param string $key Cache key.
	 * @return mixed
	 */
	public function get( string $key ): mixed {
		$value = $this->redis->get( $this->prefix . $key );

		if ( false === $value ) {
			return null;
		}

		return is_numeric( $value ) ? (int) $value : $value;
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
		if ( $ttl > 0 ) {
			return $this->redis->setex( $this->prefix . $key, $ttl, $value );
		}

		return $this->redis->set( $this->prefix . $key, $value );
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
		$value    = $this->redis->incr( $full_key );

		// Set TTL only on first increment (when value becomes 1).
		if ( 1 === $value && $ttl > 0 ) {
			$this->redis->expire( $full_key, $ttl );
		}

		return (int) $value;
	}

	/**
	 * Check if Redis extension is available and connectable.
	 *
	 * @return bool
	 */
	public static function is_available(): bool {
		if ( ! class_exists( '\Redis' ) ) {
			return false;
		}

		try {
			$redis = new \Redis();
			$ok    = $redis->connect( '127.0.0.1', 6379, 0.5 );

			if ( ! $ok ) {
				return false;
			}

			// Verify we can actually run commands (fails if auth is required).
			$redis->ping();
			$redis->close();
			return true;
		} catch ( \Throwable $e ) {
			return false;
		}
	}
}
