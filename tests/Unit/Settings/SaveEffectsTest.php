<?php
/**
 * Tests for the post-save side effects.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings;

use LightweightPlugins\Firewall\Settings\PinnedValues;
use LightweightPlugins\Firewall\Settings\SaveEffects;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Settings\SaveEffects
 * @covers \LightweightPlugins\Firewall\Settings\PinnedValues
 */
final class SaveEffectsTest extends TestCase {

	/**
	 * @dataProvider provide_seed_cases
	 *
	 * @param bool $before   Alerts on before the write.
	 * @param bool $after    Alerts on after the write.
	 * @param bool $seeded   Baseline already exists.
	 * @param bool $expected Whether to seed.
	 */
	public function test_seeds_only_when_alerts_are_switched_on_without_a_baseline( bool $before, bool $after, bool $seeded, bool $expected ): void {
		$this->assertSame(
			$expected,
			SaveEffects::needs_seed( array( 'admin_alert_enabled' => $before ), array( 'admin_alert_enabled' => $after ), $seeded )
		);
	}

	/**
	 * @return array<string, array{0: bool, 1: bool, 2: bool, 3: bool}>
	 */
	public static function provide_seed_cases(): array {
		return array(
			'off to on, no baseline' => array( false, true, false, true ),
			'off to on, seeded'      => array( false, true, true, false ),
			'on to on'               => array( true, true, false, false ),
			'on to off'              => array( true, false, false, false ),
		);
	}

	public function test_a_reset_keeps_the_stored_value_of_a_pinned_key(): void {
		$values = PinnedValues::keep(
			array(
				'rate_limit'  => 30,
				'rate_window' => 60,
			),
			array(
				'rate_limit'  => 99,
				'rate_window' => 10,
			),
			array( 'rate_limit' )
		);

		$this->assertSame(
			array(
				'rate_limit'  => 99,
				'rate_window' => 60,
			),
			$values
		);
	}
}
