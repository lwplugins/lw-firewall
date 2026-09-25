<?php
/**
 * Tests for when geo blocking counts as active (.htaccess rules, weekly cron).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Geo;

use LightweightPlugins\Firewall\Geo\GeoActivation;
use LightweightPlugins\Firewall\Geo\HtaccessWriter;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Geo\GeoActivation
 * @covers \LightweightPlugins\Firewall\Geo\HtaccessWriter
 */
final class GeoActivationTest extends TestCase {

	/**
	 * @return array<string, array{0: array<string, mixed>, 1: bool}>
	 */
	public static function provide_options(): array {
		$on = [
			'enabled'           => true,
			'geo_enabled'       => true,
			'blocked_countries' => [ 'CN' ],
		];

		return [
			'everything on'          => [ $on, true ],
			'master switch off'      => [ array_merge( $on, [ 'enabled' => false ] ), false ],
			'geo blocking off'       => [ array_merge( $on, [ 'geo_enabled' => false ] ), false ],
			'no countries'           => [ array_merge( $on, [ 'blocked_countries' => [] ] ), false ],
			'only invalid countries' => [ array_merge( $on, [ 'blocked_countries' => [ 'Germany' ] ] ), false ],
		];
	}

	/**
	 * @dataProvider provide_options
	 *
	 * @param array<string, mixed> $options  Effective settings.
	 * @param bool                 $expected Whether geo blocking is active.
	 */
	public function test_geo_blocking_is_active_only_when_every_switch_is_on( array $options, bool $expected ): void {
		$this->assertSame( $expected, GeoActivation::is_active( $options ) );
	}

	/**
	 * The bug: the CF-IPCountry block was written with the master switch off,
	 * so Apache kept refusing visitors of the listed countries while the
	 * plugin reported the firewall disabled.
	 *
	 * @dataProvider provide_options
	 *
	 * @param array<string, mixed> $options  Effective settings.
	 * @param bool                 $expected Whether rules should be written.
	 */
	public function test_htaccess_rules_are_written_only_while_active( array $options, bool $expected ): void {
		$this->assertSame( $expected, [] !== HtaccessWriter::rules_for( $options ) );
	}

	/**
	 * @dataProvider provide_cron_states
	 *
	 * @param bool   $active    Whether geo blocking is active.
	 * @param bool   $scheduled Whether the weekly event exists.
	 * @param string $expected  Action to take.
	 */
	public function test_decides_what_to_do_with_the_weekly_cron( bool $active, bool $scheduled, string $expected ): void {
		$this->assertSame( $expected, GeoActivation::cron_action( $active, $scheduled ) );
	}

	/**
	 * @return array<string, array{0: bool, 1: bool, 2: string}>
	 */
	public static function provide_cron_states(): array {
		return [
			'active, not scheduled'   => [ true, false, GeoActivation::SCHEDULE ],
			'active, scheduled'       => [ true, true, GeoActivation::KEEP ],
			'inactive, scheduled'     => [ false, true, GeoActivation::UNSCHEDULE ],
			'inactive, not scheduled' => [ false, false, GeoActivation::KEEP ],
		];
	}
}
