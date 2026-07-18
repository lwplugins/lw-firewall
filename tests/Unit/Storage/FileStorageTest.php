<?php
/**
 * Regression tests for the file storage counter.
 *
 * Runs in a separate process because it defines WP_CONTENT_DIR (the storage
 * root) and writes real cache files.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Storage;

use LightweightPlugins\Firewall\Storage\FileStorage;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Storage\FileStorage
 *
 * @runInSeparateProcess
 * @preserveGlobalState disabled
 */
final class FileStorageTest extends TestCase {

	public function test_increment_counts_sequentially_and_stores_values(): void {
		$base = sys_get_temp_dir() . '/lwfw_fs_' . uniqid();
		mkdir( $base, 0777, true );
		define( 'WP_CONTENT_DIR', $base );

		$storage = new FileStorage();

		// A fresh key starts at 1 and each atomic increment adds exactly one.
		$this->assertSame( 1, $storage->increment( 'flood_key', 60 ) );
		$this->assertSame( 2, $storage->increment( 'flood_key', 60 ) );
		$this->assertSame( 3, $storage->increment( 'flood_key', 60 ) );

		// An independent key has its own counter.
		$this->assertSame( 1, $storage->increment( 'other_key', 60 ) );

		// set()/get() round-trips a value.
		$this->assertTrue( $storage->set( 'val', 'hello', 60 ) );
		$this->assertSame( 'hello', $storage->get( 'val' ) );

		// A missing key reads back as null.
		$this->assertNull( $storage->get( 'no_such_key' ) );

		$this->cleanup( $base );
	}

	private function cleanup( string $dir ): void {
		$files = glob( $dir . '/cache/lw-firewall/*' );

		if ( is_array( $files ) ) {
			foreach ( $files as $file ) {
				@unlink( $file );
			}
		}

		@rmdir( $dir . '/cache/lw-firewall' );
		@rmdir( $dir . '/cache' );
		@rmdir( $dir );
	}
}
