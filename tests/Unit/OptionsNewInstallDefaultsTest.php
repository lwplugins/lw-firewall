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

	/**
	 * A new install gets the full defaults row from activation, so it is on.
	 */
	public function test_a_new_install_protects_xmlrpc(): void {
		Functions\when( 'get_option' )->justReturn( Options::get_defaults() );

		$this->assertTrue( Options::get_stored()['protect_xmlrpc'] );
	}

	/**
	 * Regression: with no stored row at all — a multisite subsite (network
	 * activation writes only the current blog's row) or a lost/corrupt row —
	 * XML-RPC protection silently switched on.
	 *
	 * @dataProvider provide_missing_rows
	 *
	 * @param mixed $row Stored option value.
	 */
	public function test_a_site_without_a_stored_row_keeps_it_off( mixed $row ): void {
		Functions\when( 'get_option' )->justReturn( $row );

		$this->assertFalse( Options::get_stored()['protect_xmlrpc'] );
	}

	/**
	 * @return array<string, array{0: mixed}>
	 */
	public static function provide_missing_rows(): array {
		return array(
			'no row'       => array( false ),
			'empty array'  => array( array() ),
			'not an array' => array( 'garbage' ),
		);
	}

	/**
	 * The worker reads the effective settings; they must agree.
	 */
	public function test_the_effective_settings_read_the_same(): void {
		Functions\when( 'get_option' )->justReturn( false );

		$this->assertFalse( Options::get_all()['protect_xmlrpc'] );
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
