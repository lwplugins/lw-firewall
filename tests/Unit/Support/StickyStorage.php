<?php
/**
 * Storage double whose deletes are refused.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Support;

use LightweightPlugins\Firewall\Storage\StorageInterface;

/**
 * Behaves like ArrayStorage except that delete() reports success and keeps
 * the value — the "storage refused the delete" case.
 */
final class StickyStorage implements StorageInterface {

	/**
	 * Backing store.
	 *
	 * @var ArrayStorage
	 */
	private ArrayStorage $inner;

	public function __construct() {
		$this->inner = new ArrayStorage();
	}

	public function get( string $key ): mixed {
		return $this->inner->get( $key );
	}

	public function set( string $key, mixed $value, int $ttl ): bool {
		return $this->inner->set( $key, $value, $ttl );
	}

	public function increment( string $key, int $ttl ): int {
		return $this->inner->increment( $key, $ttl );
	}

	public function delete( string $key ): bool {
		return false;
	}

	public static function is_available(): bool {
		return true;
	}
}
