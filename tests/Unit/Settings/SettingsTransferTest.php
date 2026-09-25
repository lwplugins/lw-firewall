<?php
/**
 * Tests for the settings import and export.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings;

use LightweightPlugins\Firewall\Settings\SettingsTransfer;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\WritePath;

/**
 * @covers \LightweightPlugins\Firewall\Settings\SettingsTransfer
 * @covers \LightweightPlugins\Firewall\Settings\SettingsWriter
 */
final class SettingsTransferTest extends MonkeyTestCase {

	/**
	 * Regression: a key missing from the file was reset to its default, so
	 * importing a partial file silently rewrote unrelated settings.
	 */
	public function test_keys_missing_from_the_file_keep_their_current_value(): void {
		$store = WritePath::install( array( 'rate_limit' => 77 ) );

		SettingsTransfer::import( array( 'enabled' => false ) );

		$this->assertSame( 77, $store->data['lw_firewall']['rate_limit'] );
	}

	/**
	 * Regression: booleans were not cast, so a JSON "false" was truthy.
	 */
	public function test_a_false_string_imports_as_false(): void {
		$store = WritePath::install();

		SettingsTransfer::import( array( 'protect_login' => 'false' ) );

		$this->assertFalse( $store->data['lw_firewall']['protect_login'] );
	}

	/**
	 * Regression: admin_alert_email and trusted_proxies were not validated.
	 */
	public function test_an_invalid_value_is_reported_and_not_imported(): void {
		$store = WritePath::install( array( 'trusted_proxies' => array( '10.0.0.1' ) ) );

		$report = SettingsTransfer::import(
			array(
				'trusted_proxies' => array( 'proxy.local' ),
				'rate_limit'      => 40,
			)
		);

		$this->assertSame( array( 'trusted_proxies' ), array_keys( $report['invalid'] ) );
		$this->assertSame( array( '10.0.0.1' ), $store->data['lw_firewall']['trusted_proxies'] );
	}

	public function test_the_valid_keys_of_a_partly_invalid_file_are_imported(): void {
		$store = WritePath::install();

		$report = SettingsTransfer::import(
			array(
				'admin_alert_email' => 'nope',
				'rate_limit'        => 40,
			)
		);

		$this->assertSame( array( 'rate_limit' ), $report['imported'] );
		$this->assertSame( 40, $store->data['lw_firewall']['rate_limit'] );
	}

	public function test_unknown_keys_are_reported(): void {
		WritePath::install();

		$report = SettingsTransfer::import(
			array(
				'rate_limit' => 40,
				'version'    => '1.5.10',
			)
		);

		$this->assertSame( array( 'version' ), $report['unknown'] );
	}

	/**
	 * A key pinned in wp-config.php is never written by an import.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_a_pinned_key_is_not_imported(): void {
		define( 'LW_FIREWALL_RATE_LIMIT', 5 );
		$store = WritePath::install( array( 'rate_limit' => 30 ) );

		$report = SettingsTransfer::import( array( 'rate_limit' => 99 ) );

		$this->assertSame( array( 'rate_limit' ), $report['locked'] );
		$this->assertSame( 30, $store->data['lw_firewall']['rate_limit'] );
	}

	/**
	 * @dataProvider provide_unusable_documents
	 *
	 * @param string $json Raw file contents.
	 */
	public function test_decode_refuses_a_document_without_settings( string $json ): void {
		$this->assertNull( SettingsTransfer::decode( $json ) );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_unusable_documents(): array {
		return array(
			'not json'      => array( '{nope' ),
			'a list'        => array( '[1,2,3]' ),
			'a scalar'      => array( '"x"' ),
			'no known keys' => array( '{"foo":1}' ),
			'empty object'  => array( '{}' ),
		);
	}

	public function test_decode_returns_the_settings_object(): void {
		$this->assertSame( array( 'rate_limit' => 10 ), SettingsTransfer::decode( '{"rate_limit":10}' ) );
	}
}
