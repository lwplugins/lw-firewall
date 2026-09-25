<?php
/**
 * Minimal phpredis stand-in for unit tests.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Support;

/**
 * Duck-typed double for the \Redis methods RedisStorage uses. Keys hold a
 * value and a TTL (-1 = none, as Redis reports it). eval() emulates the one
 * script RedisStorage sends; `$eval_disabled` makes it fail like a server with
 * scripting turned off, `$throw` makes every call throw like a dropped
 * connection.
 */
final class FakeRedis {

	/**
	 * Stored values.
	 *
	 * @var array<string, mixed>
	 */
	public array $values = array();

	/**
	 * TTL per key; -1 when the key never expires.
	 *
	 * @var array<string, int>
	 */
	public array $ttls = array();

	/**
	 * Names of the commands received, in order.
	 *
	 * @var array<int, string>
	 */
	public array $calls = array();

	public bool $eval_disabled = false;

	public bool $throw = false;

	/**
	 * Record a call, or throw when the connection is "down".
	 *
	 * @param string $name Command.
	 * @return void
	 */
	private function call( string $name ): void {
		$this->calls[] = $name;

		if ( $this->throw ) {
			throw new \RuntimeException( 'Connection lost' );
		}
	}

	public function get( string $key ): mixed {
		$this->call( 'get' );
		return $this->values[ $key ] ?? false;
	}

	public function set( string $key, mixed $value ): bool {
		$this->call( 'set' );
		$this->values[ $key ] = $value;
		$this->ttls[ $key ]   = -1;
		return true;
	}

	public function setex( string $key, int $ttl, mixed $value ): bool {
		$this->call( 'setex' );
		$this->values[ $key ] = $value;
		$this->ttls[ $key ]   = $ttl;
		return true;
	}

	public function incr( string $key ): int {
		$this->call( 'incr' );
		$this->values[ $key ] = (int) ( $this->values[ $key ] ?? 0 ) + 1;
		$this->ttls[ $key ]   = $this->ttls[ $key ] ?? -1;
		return $this->values[ $key ];
	}

	public function ttl( string $key ): int {
		$this->call( 'ttl' );
		return isset( $this->values[ $key ] ) ? $this->ttls[ $key ] : -2;
	}

	public function expire( string $key, int $ttl ): bool {
		$this->call( 'expire' );
		$this->ttls[ $key ] = $ttl;
		return true;
	}

	public function del( string $key ): int {
		$this->call( 'del' );
		unset( $this->values[ $key ], $this->ttls[ $key ] );
		return 1;
	}

	/**
	 * Emulates the increment script: INCR, then EXPIRE when no TTL is set.
	 *
	 * @param string            $script   Lua source (only inspected for INCR).
	 * @param array<int, mixed> $args     Keys followed by arguments.
	 * @param int               $num_keys Number of keys in $args.
	 * @return mixed
	 */
	public function eval( string $script, array $args = array(), int $num_keys = 0 ): mixed {
		$this->call( 'eval' );

		if ( $this->eval_disabled || ! str_contains( $script, 'INCR' ) || 1 !== $num_keys ) {
			return false;
		}

		$key                  = (string) $args[0];
		$this->values[ $key ] = (int) ( $this->values[ $key ] ?? 0 ) + 1;

		if ( -1 === ( $this->ttls[ $key ] ?? -1 ) ) {
			$this->ttls[ $key ] = (int) $args[1];
		}

		return $this->values[ $key ];
	}
}
