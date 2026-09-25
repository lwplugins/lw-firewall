<?php
/**
 * Tests for the admin API settings store.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings;

use LightweightPlugins\Firewall\Settings\SettingsStore;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\WritePath;

/**
 * @covers \LightweightPlugins\Firewall\Settings\SettingsStore
 */
final class SettingsStoreTest extends MonkeyTestCase {

	/**
	 * A partial update must not touch what the client did not send — the
	 * classic form turned every absent checkbox into false.
	 */
	public function test_a_key_that_was_not_sent_keeps_its_stored_value(): void {
		$store = WritePath::install( array( 'protect_login' => true ) );

		SettingsStore::save( array( 'rate_limit' => 40 ) );

		$this->assertTrue( $store->data['lw_firewall']['protect_login'] );
	}

	public function test_saves_the_submitted_keys(): void {
		$store = WritePath::install();

		SettingsStore::save( array( 'rate_limit' => '40' ) );

		$this->assertSame( 40, $store->data['lw_firewall']['rate_limit'] );
	}

	/**
	 * Atomic: one invalid field means nothing is saved.
	 */
	public function test_saves_nothing_when_any_field_is_invalid(): void {
		$store = WritePath::install( array( 'rate_limit' => 30 ) );

		SettingsStore::save(
			array(
				'rate_limit'        => 40,
				'blocked_countries' => 'Germany',
			)
		);

		$this->assertSame( 30, $store->data['lw_firewall']['rate_limit'] );
	}

	public function test_returns_the_errors_per_field(): void {
		WritePath::install();

		$errors = SettingsStore::save( array( 'blocked_countries' => 'Germany' ) );

		$this->assertSame( array( 'blocked_countries' ), array_keys( $errors ) );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_ignores_a_key_pinned_in_wp_config(): void {
		define( 'LW_FIREWALL_RATE_LIMIT', 5 );
		$store = WritePath::install( array( 'rate_limit' => 30 ) );

		SettingsStore::save( array( 'rate_limit' => 40 ) );

		$this->assertSame( 30, $store->data['lw_firewall']['rate_limit'] );
	}

	/**
	 * @dataProvider provide_typed_values
	 *
	 * @param mixed $stored   Stored value.
	 * @param mixed $default  Default value.
	 * @param mixed $expected Typed value.
	 */
	public function test_types_values_like_their_defaults( mixed $stored, mixed $default, mixed $expected ): void {
		$this->assertSame( array( 'k' => $expected ), SettingsStore::typed( array( 'k' => $stored ), array( 'k' => $default ) ) );
	}

	/**
	 * @return array<string, array{0: mixed, 1: mixed, 2: mixed}>
	 */
	public static function provide_typed_values(): array {
		return array(
			'bool from 1'        => array( 1, false, true ),
			'bool from "0"'      => array( '0', true, false ),
			'int from string'    => array( '45', 30, 45 ),
			'int from junk'      => array( 'x', 30, 30 ),
			'list re-indexed'    => array( array( 2 => 'a', 5 => 'b' ), array(), array( 'a', 'b' ) ),
			'list from scalar'   => array( 'a', array(), array() ),
			'list drops arrays'  => array( array( 'a', array( 'b' ) ), array(), array( 'a' ) ),
			'string from int'    => array( 5, '', '5' ),
		);
	}
}
