<?php
/**
 * Regression test for the geo CIDR-cache include path (LFI hardening).
 *
 * Runs in a separate process because it defines WP_CONTENT_DIR (consumed by
 * CidrUpdater::get_cache_dir()) and includes real fixture files.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Geo;

use LightweightPlugins\Firewall\Geo\GeoDetector;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Geo\GeoDetector
 */
final class GeoDetectorTest extends TestCase {

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_traversal_country_code_is_never_included(): void {
		$base = sys_get_temp_dir() . '/lwfw_geo_' . uniqid();
		$geo  = $base . '/cache/lw-firewall/geo/';
		mkdir( $geo, 0777, true );

		define( 'WP_CONTENT_DIR', $base );

		// A sentinel PHP file outside the geo cache dir, reachable via traversal.
		// If include() ever runs it, it flips a global and returns a match-all CIDR.
		file_put_contents(
			$base . '/pwned.php',
			"<?php \$GLOBALS['lw_test_lfi_ran'] = true; return array( '0.0.0.0/0' );\n"
		);

		// A legitimate cache file proving the include mechanism still works.
		file_put_contents( $geo . 'xx.php', "<?php return array( '1.2.3.4/32' );\n" );

		unset( $_SERVER['HTTP_CF_IPCOUNTRY'] );

		// Negative: the traversal code must be rejected before include().
		$blocked = GeoDetector::is_blocked( '1.2.3.4', array( '../../../pwned' ) );

		$this->assertFalse( $blocked, 'Traversal country code must not block.' );
		$this->assertArrayNotHasKey(
			'lw_test_lfi_ran',
			$GLOBALS,
			'The sentinel file was include()d — path traversal reached the sink.'
		);

		// Positive control: a valid code still loads its cache and matches.
		$this->assertTrue( GeoDetector::is_blocked( '1.2.3.4', array( 'XX' ) ) );

		// Cleanup.
		@unlink( $geo . 'xx.php' );
		@unlink( $base . '/pwned.php' );
		@rmdir( $geo );
		@rmdir( $base . '/cache/lw-firewall' );
		@rmdir( $base . '/cache' );
		@rmdir( $base );
	}
}
