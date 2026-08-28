<?php
/**
 * Tests for the server-side option value policy.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use LightweightPlugins\Firewall\OptionSchema;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\OptionSchema
 */
final class OptionSchemaTest extends TestCase {

	/**
	 * Regression: the admin form's only numeric bounds were the HTML min/max
	 * attributes, which a browser enforces and nothing else does. A crafted
	 * POST or a CLI call could store a zero ban duration, which every storage
	 * backend reads as "no TTL" — a ban nothing would ever lift.
	 */
	public function test_a_zero_ban_duration_is_clamped_to_the_minimum(): void {
		$this->assertSame( 60, OptionSchema::apply( 'auto_ban_duration', 0 ) );
		$this->assertSame( 60, OptionSchema::apply( 'reset_ban_duration', 0 ) );
		$this->assertSame( 60, OptionSchema::apply( 'login_lockout_duration', -99 ) );
	}

	public function test_an_absurd_value_is_clamped_to_the_maximum(): void {
		$this->assertSame( 2592000, OptionSchema::apply( 'auto_ban_duration', 999999999 ) );
	}

	public function test_a_value_inside_the_range_is_kept(): void {
		$this->assertSame( 1800, OptionSchema::apply( 'auto_ban_duration', 1800 ) );
	}

	/**
	 * Limits that are documented as "0 disables this axis" must keep accepting
	 * zero — clamping is not the same as a blanket minimum.
	 */
	public function test_a_limit_that_zero_disables_still_accepts_zero(): void {
		$this->assertSame( 0, OptionSchema::apply( 'reset_user_max', 0 ) );
		$this->assertSame( 0, OptionSchema::apply( 'reset_global_max', 0 ) );
	}

	public function test_a_non_numeric_value_becomes_the_minimum(): void {
		$this->assertSame( 1, OptionSchema::apply( 'rate_limit', 'not a number' ) );
	}

	/**
	 * @dataProvider provide_enums
	 *
	 * @param string $key      Option key.
	 * @param mixed  $value    Candidate.
	 * @param mixed  $expected Result.
	 */
	public function test_enum_values_are_allowlisted( string $key, mixed $value, mixed $expected ): void {
		$this->assertSame( $expected, OptionSchema::apply( $key, $value, 'auto' ) );
	}

	/**
	 * @return array<string, array{0: string, 1: mixed, 2: mixed}>
	 */
	public static function provide_enums(): array {
		return array(
			'valid storage'   => array( 'storage', 'redis', 'redis' ),
			'cased storage'   => array( 'storage', 'Redis', 'redis' ),
			'padded storage'  => array( 'storage', ' file ', 'file' ),
			'unknown storage' => array( 'storage', 'memcached', 'auto' ),
			'valid action'    => array( 'action', '429', '429' ),
			'unknown action'  => array( 'action', 'explode', 'auto' ),
			'valid header'    => array( 'proxy_header', 'x-real-ip', 'x-real-ip' ),
			'unknown header'  => array( 'proxy_header', 'x-client-ip', 'auto' ),
			'array given'     => array( 'storage', array( 'redis' ), 'auto' ),
		);
	}

	/**
	 * Lists and booleans have no range or enum, so the policy must pass them
	 * through untouched rather than mangling them into integers.
	 */
	public function test_untyped_options_pass_through(): void {
		$this->assertTrue( OptionSchema::apply( 'enabled', true ) );
		$this->assertSame(
			array( '10.0.0.0/8' ),
			OptionSchema::apply( 'ip_whitelist', array( '10.0.0.0/8' ) )
		);
	}

	public function test_applies_to_a_whole_configuration(): void {
		$result = OptionSchema::apply_all(
			array(
				'auto_ban_duration' => 0,
				'storage'           => 'nope',
				'enabled'           => false,
			),
			array( 'storage' => 'file' )
		);

		$this->assertSame( 60, $result['auto_ban_duration'] );
		$this->assertSame( 'file', $result['storage'] );
		$this->assertFalse( $result['enabled'] );
	}
}
