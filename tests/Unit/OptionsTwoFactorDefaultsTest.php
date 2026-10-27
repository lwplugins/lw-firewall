<?php
/**
 * Tests for the two-factor option defaults and value policy.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\OptionSchema;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Settings\Input\OptionInput;

/**
 * @covers \LightweightPlugins\Firewall\Options
 * @covers \LightweightPlugins\Firewall\OptionSchema
 * @covers \LightweightPlugins\Firewall\Settings\Input\OptionInput
 * @covers \LightweightPlugins\Firewall\Settings\Input\RoleListParser
 */
final class OptionsTwoFactorDefaultsTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();

		Functions\stubTranslationFunctions();
		Functions\when( 'sanitize_key' )->alias(
			static fn ( $key ): string => (string) preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) )
		);
	}

	public function test_twofa_defaults(): void {
		$defaults = Options::get_defaults();

		$this->assertFalse( $defaults['twofa_enabled'] );
		$this->assertSame( [], $defaults['twofa_required_roles'] );
		$this->assertSame( 7, $defaults['twofa_grace_days'] );
		$this->assertSame( 0, $defaults['twofa_remember_days'] );
		$this->assertFalse( $defaults['twofa_block_app_passwords'] );
		$this->assertTrue( $defaults['twofa_passkey_login'] );
	}

	public function test_twofa_ranges(): void {
		$ranges = OptionSchema::ranges();

		$this->assertSame( [ 0, 90 ], $ranges['twofa_grace_days'] );
		$this->assertSame( [ 0, 90 ], $ranges['twofa_remember_days'] );
	}

	public function test_a_stored_role_string_is_read_as_a_list(): void {
		Functions\when( 'get_option' )->justReturn( [ 'twofa_required_roles' => "administrator\neditor" ] );

		$this->assertSame( [ 'administrator', 'editor' ], Options::get_all()['twofa_required_roles'] );
	}

	public function test_existing_install_without_the_keys_gets_two_factor_off(): void {
		Functions\when( 'get_option' )->justReturn( [ 'enabled' => true ] );

		$this->assertFalse( Options::get_stored()['twofa_enabled'] );
	}

	public function test_settings_input_parses_the_new_keys(): void {
		$report = OptionInput::parse(
			[
				'twofa_enabled'        => 'true',
				'twofa_required_roles' => 'Administrator, shop_manager, !!',
				'twofa_grace_days'     => '14',
				'twofa_remember_days'  => '0',
				'twofa_passkey_login'  => false,
			]
		);

		$this->assertSame( [ 'twofa_required_roles' ], array_keys( $report->errors() ) );

		$report = OptionInput::parse(
			[
				'twofa_enabled'            => 'true',
				'twofa_required_roles'     => [ 'Administrator', 'shop_manager', 'administrator' ],
				'twofa_grace_days'         => '14',
				'twofa_block_app_passwords' => true,
			]
		);

		$this->assertSame(
			[
				'twofa_enabled'             => true,
				'twofa_required_roles'      => [ 'administrator', 'shop_manager' ],
				'twofa_grace_days'          => 14,
				'twofa_block_app_passwords' => true,
			],
			$report->values()
		);
	}

	public function test_grace_days_out_of_range_is_an_error(): void {
		$report = OptionInput::parse( [ 'twofa_grace_days' => 91 ] );

		$this->assertSame( [ 'twofa_grace_days' ], array_keys( $report->errors() ) );
		$this->assertSame( 90, OptionSchema::apply( 'twofa_grace_days', 500 ) );
	}
}
