<?php
/**
 * Tests for the wp-config.php constant overlay.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Options;

/**
 * @covers \LightweightPlugins\Firewall\Options
 */
final class OptionsOverrideTest extends MonkeyTestCase {

	/**
	 * Pin one option from "wp-config.php". Constants are process-global, so a
	 * key no other test asserts on is used, and it is defined once.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'LW_FIREWALL_RATE_WINDOW' ) ) {
			define( 'LW_FIREWALL_RATE_WINDOW', 5 );
		}

		Functions\when( 'get_option' )->justReturn( array( 'rate_window' => 999 ) );
	}

	/**
	 * Regression: get() honoured constants but get_all() did not, so the worker,
	 * the hook bootstrap and the .htaccess sync all ran on the stored value
	 * while the operator believed the constant was in force.
	 */
	public function test_the_effective_config_applies_the_constant(): void {
		$this->assertSame( 5, Options::get_all()['rate_window'] );
	}

	public function test_a_single_read_applies_the_constant_too(): void {
		$this->assertSame( 5, Options::get( 'rate_window' ) );
	}

	/**
	 * Saving must never see the constant, or the pinned value would be written
	 * into the database as if it had been chosen there — and would survive the
	 * constant being removed.
	 */
	public function test_the_stored_config_keeps_the_database_value(): void {
		$this->assertSame( 999, Options::get_stored()['rate_window'] );
	}

	public function test_an_unpinned_option_reads_the_same_either_way(): void {
		$this->assertSame(
			Options::get_stored()['rate_limit'],
			Options::get_all()['rate_limit']
		);
	}

	public function test_pinned_keys_are_reported_for_the_admin(): void {
		$this->assertContains( 'rate_window', Options::overridden() );
		$this->assertNotContains( 'rate_limit', Options::overridden() );
	}
}
