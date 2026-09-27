<?php
/**
 * Tests for the filter cookie default on existing installs.
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
final class OptionsFilterCookieDefaultTest extends MonkeyTestCase {

	public function test_an_existing_install_gets_the_filter_cookie_check_on(): void {
		Functions\when( 'get_option' )->justReturn( [ 'enabled' => true ] );

		$this->assertTrue( Options::get_stored()['filter_require_cookie'] );
	}

	public function test_a_saved_off_value_is_kept(): void {
		Functions\when( 'get_option' )->justReturn( [ 'filter_require_cookie' => false ] );

		$this->assertFalse( Options::get_stored()['filter_require_cookie'] );
	}

	public function test_a_new_install_gets_the_add_to_cart_check_on(): void {
		Functions\when( 'get_option' )->justReturn( Options::get_defaults() );

		$this->assertTrue( Options::get_stored()['add_to_cart_require_cookie'] );
	}

	public function test_an_existing_install_keeps_the_add_to_cart_check_off(): void {
		Functions\when( 'get_option' )->justReturn( [ 'enabled' => true ] );

		$this->assertFalse( Options::get_stored()['add_to_cart_require_cookie'] );
	}

	public function test_a_saved_on_add_to_cart_value_is_kept(): void {
		Functions\when( 'get_option' )->justReturn( [ 'add_to_cart_require_cookie' => true ] );

		$this->assertTrue( Options::get_stored()['add_to_cart_require_cookie'] );
	}
}
