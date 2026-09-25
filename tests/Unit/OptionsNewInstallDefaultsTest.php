<?php
/**
 * Tests for defaults that differ between new and existing installs.
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
final class OptionsNewInstallDefaultsTest extends MonkeyTestCase {

	public function test_a_new_install_protects_xmlrpc(): void {
		Functions\when( 'get_option' )->justReturn( false );

		$this->assertTrue( Options::get_stored()['protect_xmlrpc'] );
	}

	/**
	 * A site whose stored settings predate the key keeps the old default:
	 * switching XML-RPC protection on under an existing site is not ours to do.
	 */
	public function test_an_existing_install_without_the_key_keeps_it_off(): void {
		Functions\when( 'get_option' )->justReturn( array( 'rate_limit' => 30 ) );

		$this->assertFalse( Options::get_stored()['protect_xmlrpc'] );
	}

	public function test_an_existing_install_keeps_its_stored_value(): void {
		Functions\when( 'get_option' )->justReturn( array( 'protect_xmlrpc' => true ) );

		$this->assertTrue( Options::get_stored()['protect_xmlrpc'] );
	}

	public function test_the_shipped_default_is_on(): void {
		$this->assertTrue( Options::get_defaults()['protect_xmlrpc'] );
	}
}
