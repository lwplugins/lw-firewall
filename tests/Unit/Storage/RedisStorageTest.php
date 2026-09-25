<?php
/**
 * Tests for the Redis storage backend (against a fake client).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Storage;

use LightweightPlugins\Firewall\Storage\RedisStorage;
use LightweightPlugins\Firewall\Storage\StorageDetector;
use LightweightPlugins\Firewall\Tests\Unit\Support\FakeRedis;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Storage\RedisStorage
 */
final class RedisStorageTest extends TestCase {

	private FakeRedis $redis;

	private RedisStorage $storage;

	protected function setUp(): void {
		parent::setUp();
		$this->redis   = new FakeRedis();
		$this->storage = new RedisStorage( '127.0.0.1', 6379, $this->redis );
	}

	private static function key( string $key ): string {
		return StorageDetector::key_prefix() . $key;
	}

	public function test_a_new_counter_starts_at_one_with_its_ttl(): void {
		$this->assertSame( 1, $this->storage->increment( 'login_1.2.3.4', 60 ) );
		$this->assertSame( 60, $this->redis->ttls[ self::key( 'login_1.2.3.4' ) ] );
	}

	public function test_a_counter_keeps_counting(): void {
		$this->storage->increment( 'k', 60 );
		$this->storage->increment( 'k', 60 );

		$this->assertSame( 3, $this->storage->increment( 'k', 60 ) );
	}

	/**
	 * The race: INCR and EXPIRE were two separate commands, and the TTL was only
	 * set when the value became 1. A crash between them left a counter that
	 * never expired — a permanent rate limit or ban trigger.
	 */
	public function test_increment_is_a_single_atomic_command(): void {
		$this->storage->increment( 'k', 60 );

		$this->assertSame( [ 'eval' ], $this->redis->calls );
	}

	/**
	 * A counter already stranded without a TTL (by the old code) is repaired
	 * the next time it is incremented.
	 */
	public function test_a_counter_without_a_ttl_gets_one_on_the_next_increment(): void {
		$this->redis->values[ self::key( 'k' ) ] = 7;
		$this->redis->ttls[ self::key( 'k' ) ]   = -1;

		$this->storage->increment( 'k', 60 );

		$this->assertSame( 60, $this->redis->ttls[ self::key( 'k' ) ] );
	}

	/**
	 * Scripting disabled on the server: fall back to INCR + EXPIRE when the
	 * key has no TTL, which still repairs a stranded counter.
	 */
	public function test_falls_back_when_scripting_is_unavailable(): void {
		$this->redis->eval_disabled = true;

		$this->storage->increment( 'k', 60 );

		$this->assertSame( 60, $this->redis->ttls[ self::key( 'k' ) ] );
	}

	public function test_increment_fails_open_when_the_connection_drops(): void {
		$this->redis->throw = true;

		$this->assertSame( 1, $this->storage->increment( 'k', 60 ) );
	}

	public function test_get_fails_open_when_the_connection_drops(): void {
		$this->redis->throw = true;

		$this->assertNull( $this->storage->get( 'ban_1.2.3.4' ) );
	}

	public function test_set_reports_failure_when_the_connection_drops(): void {
		$this->redis->throw = true;

		$this->assertFalse( $this->storage->set( 'ban_1.2.3.4', 1, 60 ) );
	}

	public function test_set_and_get_round_trip(): void {
		$this->storage->set( 'ban_1.2.3.4', 1, 60 );

		$this->assertSame( 1, $this->storage->get( 'ban_1.2.3.4' ) );
	}
}
