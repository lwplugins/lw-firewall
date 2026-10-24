<?php
/**
 * Tests for which site may write the shared .htaccess.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Geo;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Geo\HtaccessWriter;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

/**
 * @covers \LightweightPlugins\Firewall\Geo\HtaccessWriter
 */
final class HtaccessWriterSiteTest extends MonkeyTestCase {

	/**
	 * Calls to insert_with_markers(), as [ path, marker, lines ].
	 *
	 * @var array<int, array{0: string, 1: string, 2: array<int, string>}>
	 */
	private array $writes = [];

	/**
	 * ABSPATH is tests/, where a committed tests/.htaccess fixture exists;
	 * insert_with_markers() is stubbed, so nothing is written to disk.
	 */
	protected function setUp(): void {
		parent::setUp();

		OptionStore::install(
			[
				'lw_firewall' => [
					'enabled'           => true,
					'geo_enabled'       => true,
					'blocked_countries' => [ 'CN' ],
				],
			]
		);

		Functions\when( 'insert_with_markers' )->alias(
			function ( string $path, string $marker, array $lines ): bool {
				$this->writes[] = [ $path, $marker, $lines ];
				return true;
			}
		);
	}

	public function test_single_site_writes_the_geo_block(): void {
		Functions\when( 'is_multisite' )->justReturn( false );

		HtaccessWriter::sync();

		$this->assertCount( 1, $this->writes );
		$this->assertSame( ABSPATH . '.htaccess', $this->writes[0][0] );
		$this->assertNotSame( [], $this->writes[0][2] );
	}

	public function test_multisite_main_site_writes_the_geo_block(): void {
		Functions\when( 'is_multisite' )->justReturn( true );
		Functions\when( 'is_main_site' )->justReturn( true );

		HtaccessWriter::sync();

		$this->assertCount( 1, $this->writes );
	}

	public function test_multisite_sub_site_never_writes(): void {
		Functions\when( 'is_multisite' )->justReturn( true );
		Functions\when( 'is_main_site' )->justReturn( false );

		HtaccessWriter::sync();
		HtaccessWriter::remove();

		$this->assertSame( [], $this->writes );
	}
}
