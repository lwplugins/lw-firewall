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
}
