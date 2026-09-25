<?php
/**
 * Tests for the option input coordinator.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings\Input;

use LightweightPlugins\Firewall\Settings\Input\OptionInput;

/**
 * @covers \LightweightPlugins\Firewall\Settings\Input\OptionInput
 * @covers \LightweightPlugins\Firewall\Settings\Input\InputReport
 */
final class OptionInputTest extends InputTestCase {

	public function test_parses_every_submitted_key_by_its_type(): void {
		$report = OptionInput::parse(
			[
				'enabled'           => 'false',
				'rate_limit'        => '50',
				'storage'           => 'FILE',
				'blocked_countries' => 'cn, ru',
				'admin_alert_email' => 'a@example.com',
			]
		);

		$this->assertSame(
			[
				'enabled'           => false,
				'rate_limit'        => 50,
				'storage'           => 'file',
				'blocked_countries' => [ 'CN', 'RU' ],
				'admin_alert_email' => 'a@example.com',
			],
			$report->values()
		);
	}

	public function test_collects_errors_per_field(): void {
		$report = OptionInput::parse(
			[
				'rate_limit'   => 0,
				'ip_whitelist' => "1.2.3.4\nnope\nstill-nope",
				'enabled'      => true,
			]
		);

		$this->assertSame( [ 'rate_limit', 'ip_whitelist' ], array_keys( $report->errors() ) );
		$this->assertCount( 2, $report->errors()['ip_whitelist'] );
	}

	public function test_a_field_with_errors_is_not_in_the_values(): void {
		$report = OptionInput::parse(
			[
				'rate_limit' => 0,
				'enabled'    => true,
			]
		);

		$this->assertSame( [ 'enabled' => true ], $report->values() );
		$this->assertTrue( $report->has_errors() );
	}

	/**
	 * A key pinned in wp-config.php is never written, whatever arrives.
	 */
	public function test_ignores_locked_keys(): void {
		$report = OptionInput::parse(
			[
				'rate_limit' => 50,
				'enabled'    => 'garbage',
			],
			[ 'enabled' ]
		);

		$this->assertSame( [ 'rate_limit' => 50 ], $report->values() );
		$this->assertSame( [ 'enabled' ], $report->locked() );
		$this->assertFalse( $report->has_errors() );
	}

	public function test_sets_aside_unknown_keys(): void {
		$report = OptionInput::parse( [ '_locale' => 'user' ] );

		$this->assertSame( [], $report->values() );
		$this->assertSame( [ '_locale' ], $report->unknown() );
	}

	/**
	 * The numeric range is the OptionSchema range — no stricter UI limits.
	 */
	public function test_uses_the_option_schema_range(): void {
		$this->assertSame( 2592000, OptionInput::parse_value( 'auto_ban_duration', 2592000 )->value() );
	}

	/**
	 * @dataProvider provide_default_keys
	 *
	 * @param string $key Option key.
	 */
	public function test_every_default_round_trips( string $key ): void {
		$default = \LightweightPlugins\Firewall\Options::get_defaults()[ $key ];

		$this->assertSame( $default, OptionInput::parse_value( $key, $default )->value() );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_default_keys(): array {
		$keys = [];

		foreach ( array_keys( \LightweightPlugins\Firewall\Options::get_defaults() ) as $key ) {
			$keys[ $key ] = [ $key ];
		}

		return $keys;
	}

	/**
	 * A list setting is capped like the import is, so one request cannot
	 * make every later request parse a huge option.
	 *
	 * @dataProvider provide_oversized_lists
	 *
	 * @param mixed $raw Oversized list.
	 */
	public function test_rejects_a_list_over_the_entry_cap( mixed $raw ): void {
		$this->assertFalse( OptionInput::parse_value( 'blocked_bots', $raw )->is_valid() );
	}

	/**
	 * @return array<string, array{0: mixed}>
	 */
	public static function provide_oversized_lists(): array {
		$entries = array();

		for ( $i = 0; $i <= OptionInput::MAX_LIST_ENTRIES; $i++ ) {
			$entries[] = 'bot' . $i;
		}

		return array(
			'array'    => array( $entries ),
			'textarea' => array( implode( "\n", $entries ) ),
		);
	}

	public function test_accepts_a_list_at_the_cap(): void {
		$this->assertTrue( OptionInput::parse_value( 'blocked_bots', array_map( static fn ( int $i ): string => 'bot' . $i, range( 1, OptionInput::MAX_LIST_ENTRIES ) ) )->is_valid() );
	}
}
