<?php
/**
 * Tests for the storage round-trip probe.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Status;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Admin\Status\EnvironmentState;
use LightweightPlugins\Firewall\Admin\Status\StorageProbe;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\StickyStorage;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Status\StorageProbe
 */
final class StorageProbeTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubTranslationFunctions();
	}

	public function test_a_working_backend_passes_and_leaves_nothing_behind(): void {
		$storage = new ArrayStorage();

		$this->assertTrue( StorageProbe::run( $storage )['ok'] );
	}

	public function test_a_backend_that_refuses_deletes_fails(): void {
		$this->assertFalse( StorageProbe::run( new StickyStorage() )['ok'] );
	}

	public function test_a_backend_that_refuses_writes_fails(): void {
		$storage = new class() implements \LightweightPlugins\Firewall\Storage\StorageInterface {
			public function get( string $key ): mixed {
				return null;
			}
			public function set( string $key, mixed $value, int $ttl ): bool {
				return false;
			}
			public function increment( string $key, int $ttl ): int {
				return 0;
			}
			public function delete( string $key ): bool {
				return true;
			}
			public static function is_available(): bool {
				return true;
			}
		};

		$this->assertFalse( StorageProbe::run( $storage )['ok'] );
	}

	public function test_an_unknown_backend_class_is_named_unknown(): void {
		$this->assertSame( 'unknown', EnvironmentState::backend_name( new ArrayStorage() ) );
	}

	/**
	 * Regression: RedisStorage::get() turns numeric strings into numbers, so
	 * a random hex token that happened to be all digits (or like "1e5")
	 * failed the read-back check on a healthy backend.
	 */
	public function test_the_probe_token_never_looks_numeric(): void {
		$storage = new class() implements \LightweightPlugins\Firewall\Storage\StorageInterface {
			/** @var array<string, mixed> */
			private array $data = array();
			/** @var array<int, string> */
			public array $written = array();
			public function get( string $key ): mixed {
				$value = $this->data[ $key ] ?? null;
				return is_string( $value ) && is_numeric( $value ) ? $value + 0 : $value;
			}
			public function set( string $key, mixed $value, int $ttl ): bool {
				$this->written[]    = (string) $value;
				$this->data[ $key ] = $value;
				return true;
			}
			public function increment( string $key, int $ttl ): int {
				return 1;
			}
			public function delete( string $key ): bool {
				unset( $this->data[ $key ] );
				return true;
			}
			public static function is_available(): bool {
				return true;
			}
		};

		for ( $i = 0; $i < 64; $i++ ) {
			StorageProbe::run( $storage );
		}

		$this->assertSame( array(), array_filter( $storage->written, static fn ( string $t ): bool => is_numeric( $t ) || ! ctype_alpha( $t[0] ) ) );
	}
}
