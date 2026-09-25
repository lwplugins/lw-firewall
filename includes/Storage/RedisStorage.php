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
 *
 * Every command is wrapped: phpredis throws RedisException when the connection
 * drops mid-request (likeliest exactly under the flood this plugin mitigates),
 * and these methods run inside WordPress hooks such as wp_login_failed and
 * template_redirect, where an uncaught exception is a fatal error. A failure
 * fails open, like the other backends.
 */
final class RedisStorage implements StorageInterface {

	/**
	 * Atomic increment: INCR, then EXPIRE whenever the key has no TTL.
	 *
	 * One server-side step, so no crash or dropped connection can leave a
	 * counter without an expiry. Checking for a missing TTL (rather than
	 * "value is 1") also repairs a counter stranded by the old two-command
	 * sequence. Plain EVAL and TTL — no Redis 7-only flags.
	 */
	private const INCREMENT_SCRIPT = "local v = redis.call('INCR', KEYS[1])\n"
		. "if redis.call('TTL', KEYS[1]) == -1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end\n"
		. 'return v';

	/**
	 * Key prefix for Redis entries.
	 *
	 * @var string
	 */
	private string $prefix;

	/**
	 * Redis client instance.
	 *
	 * @var \Redis
	 */
	private object $redis;

	/**
	 * Whether the connection succeeded.
	 *
	 * @var bool
	 */
	private bool $connected = false;

	/**
	 * Connect to Redis on construction.
	 *
	 * A failed connection (server down, timeout, max-clients) must never fatal
	 * the front end: phpredis throws RedisException on connect failure, so we
	 * catch it and degrade to a no-op (fail-open) instead.
	 *
	 * @param string      $host   Redis host.
	 * @param int         $port   Redis port.
	 * @param \Redis|null $client Already-connected client (tests); a new one is opened when null.
	 */
	public function __construct( string $host = '127.0.0.1', int $port = 6379, ?object $client = null ) {
		$this->prefix = StorageDetector::key_prefix();

		if ( null !== $client ) {
			$this->redis     = $client;
			$this->connected = true;
			return;
		}

		$this->redis = new \Redis();

		try {
			$this->connected = (bool) $this->redis->connect( $host, $port, 1.0 ); // 1s timeout.
		} catch ( \Throwable $e ) {
			$this->connected = false;
		}
	}

	/**
	 * Get a value by key.
	 *
	 * @param string $key Cache key.
	 * @return mixed
	 */
	public function get( string $key ): mixed {
		if ( ! $this->connected ) {
			return null;
		}

		try {
			$value = $this->redis->get( $this->prefix . $key );
		} catch ( \Throwable $e ) {
			return null;
		}

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
		if ( ! $this->connected ) {
			return false;
		}

		try {
			if ( $ttl > 0 ) {
				return (bool) $this->redis->setex( $this->prefix . $key, $ttl, $value );
			}

			return (bool) $this->redis->set( $this->prefix . $key, $value );
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * Increment a counter. Returns the new value.
	 *
	 * @param string $key Cache key.
	 * @param int    $ttl Time-to-live in seconds.
	 * @return int
	 */
	public function increment( string $key, int $ttl ): int {
		// Fail-open when disconnected: a value of 1 reads as "first hit, allowed"
		// so a Redis outage degrades rate limiting rather than blocking traffic.
		if ( ! $this->connected ) {
			return 1;
		}

		$full_key = $this->prefix . $key;

		try {
			$value = $this->redis->eval( self::INCREMENT_SCRIPT, [ $full_key, max( 1, $ttl ) ], 1 );

			if ( is_int( $value ) ) {
				return $value;
			}

			return $this->increment_without_script( $full_key, $ttl );
		} catch ( \Throwable $e ) {
			return 1;
		}
	}

	/**
	 * Fallback for servers with scripting disabled.
	 *
	 * Not atomic, but self-healing: any increment that finds the key without a
	 * TTL sets one, so a counter can be stranded for at most one step.
	 *
	 * @param string $full_key Prefixed key.
	 * @param int    $ttl      Time-to-live in seconds.
	 * @return int
	 */
	private function increment_without_script( string $full_key, int $ttl ): int {
		$value = (int) $this->redis->incr( $full_key );

		if ( $ttl > 0 && -1 === (int) $this->redis->ttl( $full_key ) ) {
			$this->redis->expire( $full_key, $ttl );
		}

		return $value;
	}

	/**
	 * Delete a key.
	 *
	 * @param string $key Cache key.
	 * @return bool
	 */
	public function delete( string $key ): bool {
		if ( ! $this->connected ) {
			return false;
		}

		try {
			$this->redis->del( $this->prefix . $key );
		} catch ( \Throwable $e ) {
			return false;
		}

		return true;
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
