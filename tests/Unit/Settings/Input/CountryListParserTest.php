<?php
/**
 * Tests for the country list parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings\Input;

use LightweightPlugins\Firewall\Settings\Input\CountryListParser;

/**
 * @covers \LightweightPlugins\Firewall\Settings\Input\CountryListParser
 */
final class CountryListParserTest extends InputTestCase {

	/**
	 * Regression: the form kept the first two letters of every line, so
	 * "Germany" was stored as GE (Georgia) without a word.
	 */
	public function test_rejects_a_country_name_instead_of_truncating_it(): void {
		$result = CountryListParser::parse( "CN\nGermany" );

		$this->assertFalse( $result->is_valid() );
		$this->assertCount( 1, $result->errors() );
		$this->assertStringContainsString( 'Germany', $result->errors()[0] );
	}

	/**
	 * Regression: "CN, RU" on one line kept only CN.
	 *
	 * @dataProvider provide_separated_lists
	 *
	 * @param mixed $raw Raw input.
	 */
	public function test_accepts_codes_separated_any_common_way( mixed $raw ): void {
		$this->assertSame( [ 'CN', 'RU', 'KP' ], CountryListParser::parse( $raw )->value() );
	}

	/**
	 * @return array<string, array{0: mixed}>
	 */
	public static function provide_separated_lists(): array {
		return [
			'one per line'   => [ "CN\nRU\r\nKP" ],
			'comma, one row' => [ 'CN, RU,KP' ],
			'spaces'         => [ 'CN RU  KP' ],
			'lower case'     => [ "cn\nru\nkp" ],
			'json array'     => [ [ 'cn', ' RU ', 'KP' ] ],
			'duplicates'     => [ "CN\nRU\ncn\nKP\nRU" ],
		];
	}

	public function test_rejects_a_well_formed_code_that_is_not_assigned(): void {
		$this->assertFalse( CountryListParser::parse( 'XX' )->is_valid() );
	}

	public function test_an_empty_input_is_an_empty_list(): void {
		$this->assertSame( [], CountryListParser::parse( '' )->value() );
	}

	public function test_reports_every_bad_entry(): void {
		$this->assertCount( 2, CountryListParser::parse( "USA\nDE\n1" )->errors() );
	}

	public function test_rejects_a_value_that_is_not_a_list(): void {
		$this->assertFalse( CountryListParser::parse( 42 )->is_valid() );
	}
}
