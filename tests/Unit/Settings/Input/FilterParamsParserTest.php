<?php
/**
 * Tests for the filter parameter list parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings\Input;

use LightweightPlugins\Firewall\Settings\Input\FilterParamsParser;

/**
 * @covers \LightweightPlugins\Firewall\Settings\Input\FilterParamsParser
 */
final class FilterParamsParserTest extends InputTestCase {

	/**
	 * Regression: an empty textarea reset to filter_ and query_type_ without
	 * their |30 limits, unlike the shipped default and the field description.
	 *
	 * @dataProvider provide_empty_inputs
	 *
	 * @param mixed $raw Empty input.
	 */
	public function test_an_empty_input_resets_to_the_real_defaults( mixed $raw ): void {
		$this->assertSame( [ 'filter_|30', 'query_type_|30' ], FilterParamsParser::parse( $raw )->value() );
	}

	/**
	 * @return array<string, array{0: mixed}>
	 */
	public static function provide_empty_inputs(): array {
		return [
			'empty string' => [ '' ],
			'blank lines'  => [ "\n  \n" ],
			'empty array'  => [ [] ],
		];
	}

	public function test_keeps_prefixes_with_and_without_a_limit(): void {
		$this->assertSame(
			[ 'add-to-cart|10', 'orderby' ],
			FilterParamsParser::parse( "add-to-cart | 10\norderby" )->value()
		);
	}

	/**
	 * @dataProvider provide_invalid_entries
	 *
	 * @param string $entry Invalid entry.
	 */
	public function test_rejects_a_malformed_limit( string $entry ): void {
		$result = FilterParamsParser::parse( $entry );

		$this->assertFalse( $result->is_valid() );
		$this->assertStringContainsString( trim( $entry ), $result->errors()[0] );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_invalid_entries(): array {
		return [
			'zero limit'     => [ 'filter_|0' ],
			'negative limit' => [ 'filter_|-5' ],
			'text limit'     => [ 'filter_|many' ],
			'empty limit'    => [ 'filter_|' ],
			'no prefix'      => [ '|10' ],
			'two limits'     => [ 'filter_|10|20' ],
			'limit too big'  => [ 'filter_|100001' ],
		];
	}
}
