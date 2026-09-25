<?php
/**
 * Tests for the per-country geo update rows.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Geo;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Admin\Geo\GeoUpdateReport;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Geo\GeoUpdateReport
 */
final class GeoUpdateReportTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubTranslationFunctions();
	}

	/**
	 * @dataProvider provide_reports
	 *
	 * @param bool   $v4      IPv4 updated.
	 * @param bool   $v6      IPv6 updated.
	 * @param bool   $written Cache written.
	 * @param string $needle  Expected message fragment.
	 */
	public function test_names_what_was_updated( bool $v4, bool $v6, bool $written, string $needle ): void {
		$row = GeoUpdateReport::row( 'CN', array( 'v4' => $v4, 'v6' => $v6, 'written' => $written ) );

		$this->assertSame( array( 'CN', $v4, $v6 ), array( $row['cc'], $row['v4'], $row['v6'] ) );
		$this->assertStringContainsString( $needle, $row['message'] );
	}

	/**
	 * @return array<string, array{0: bool, 1: bool, 2: bool, 3: string}>
	 */
	public static function provide_reports(): array {
		return array(
			'both'     => array( true, true, true, 'IPv4 and IPv6' ),
			'v4 only'  => array( true, false, true, 'IPv6 list could not' ),
			'v6 only'  => array( false, true, true, 'IPv4 list could not' ),
			'nothing'  => array( false, false, false, 'Update failed' ),
		);
	}
}
