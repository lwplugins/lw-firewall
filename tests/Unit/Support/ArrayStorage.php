<?php
/**
 * In-memory StorageInterface double for unit tests.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Support;

use LightweightPlugins\Firewall\Storage\StorageInterface;

/**
 * Simple array-backed storage. increment() is atomic within a single process,
 * which is what the rate-limit / single-use logic relies on.
 */
final class ArrayStorage implements StorageInterface {

	/**
	 * Backing store.
	 *
	 * @var array<string, mixed>
	 */
	private array $data = array();

	/**
	 * @param string $key Key.
	 * @return mixed
	 */
	public function get( string $key ): mixed {
		return $this->data[ $key ] ?? null;
	}

	/**
	 * @param string $key   Key.
	 * @param mixed  $value Value.
	 * @param int    $ttl   TTL seconds (ignored in-memory).
	 * @return bool
	 */
	public function set( string $key, mixed $value, int $ttl ): bool {
		$this->data[ $key ] = $value;
		return true;
	}

	/**
	 * @param string $key Key.
	 * @param int    $ttl TTL seconds (ignored in-memory).
	 * @return int
	 */
	public function increment( string $key, int $ttl ): int {
		$this->data[ $key ] = (int) ( $this->data[ $key ] ?? 0 ) + 1;
		return $this->data[ $key ];
	}

	/**
	 * @return bool
	 */
	public static function is_available(): bool {
		return true;
	}
}
