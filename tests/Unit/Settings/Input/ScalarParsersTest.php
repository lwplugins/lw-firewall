<?php
/**
 * Tests for the boolean, integer and enum parsers.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings\Input;

use LightweightPlugins\Firewall\Settings\Input\BoolParser;
use LightweightPlugins\Firewall\Settings\Input\EnumParser;
use LightweightPlugins\Firewall\Settings\Input\IntParser;

/**
 * @covers \LightweightPlugins\Firewall\Settings\Input\BoolParser
 * @covers \LightweightPlugins\Firewall\Settings\Input\IntParser
 * @covers \LightweightPlugins\Firewall\Settings\Input\EnumParser
 */
final class ScalarParsersTest extends InputTestCase {

	/**
	 * Regression: a JSON "false" string was truthy in the import.
	 *
	 * @dataProvider provide_booleans
	 *
	 * @param mixed $raw      Raw value.
	 * @param bool  $expected Parsed value.
	 */
	public function test_casts_booleans_strictly( mixed $raw, bool $expected ): void {
		$this->assertSame( $expected, BoolParser::parse( $raw )->value() );
	}

	/**
	 * @return array<string, array{0: mixed, 1: bool}>
	 */
	public static function provide_booleans(): array {
		return [
			'true'           => [ true, true ],
			'false'          => [ false, false ],
			'int 1'          => [ 1, true ],
			'int 0'          => [ 0, false ],
			'string "false"' => [ 'false', false ],
			'string "0"'     => [ '0', false ],
			'string "FALSE"' => [ ' FALSE ', false ],
			'string "off"'   => [ 'off', false ],
			'string "no"'    => [ 'no', false ],
			'empty string'   => [ '', false ],
			'string "true"'  => [ 'true', true ],
			'string "1"'     => [ '1', true ],
			'string "yes"'   => [ 'yes', true ],
			'string "on"'    => [ 'on', true ],
		];
	}

	/**
	 * @dataProvider provide_non_booleans
	 *
	 * @param mixed $raw Raw value.
	 */
	public function test_rejects_a_value_that_is_not_a_boolean( mixed $raw ): void {
		$this->assertFalse( BoolParser::parse( $raw )->is_valid() );
	}

	/**
	 * @return array<string, array{0: mixed}>
	 */
	public static function provide_non_booleans(): array {
		return [
			'word'  => [ 'maybe' ],
			'int 2' => [ 2 ],
			'array' => [ [ true ] ],
			'null'  => [ null ],
		];
	}

	/**
	 * @dataProvider provide_integers
	 *
	 * @param mixed $raw      Raw value.
	 * @param int   $expected Parsed value.
	 */
	public function test_accepts_whole_numbers_in_range( mixed $raw, int $expected ): void {
		$this->assertSame( $expected, IntParser::parse( $raw, 1, 100 )->value() );
	}

	/**
	 * @return array<string, array{0: mixed, 1: int}>
	 */
	public static function provide_integers(): array {
		return [
			'int'          => [ 50, 50 ],
			'numeric text' => [ ' 50 ', 50 ],
			'whole float'  => [ 50.0, 50 ],
			'lower bound'  => [ 1, 1 ],
			'upper bound'  => [ '100', 100 ],
		];
	}

	/**
	 * Out-of-range values are errors, not silent clamps: the UI and the API
	 * share the OptionSchema range, so anything outside it is a mistake.
	 *
	 * @dataProvider provide_bad_integers
	 *
	 * @param mixed $raw Raw value.
	 */
	public function test_rejects_bad_numbers( mixed $raw ): void {
		$this->assertFalse( IntParser::parse( $raw, 1, 100 )->is_valid() );
	}

	/**
	 * @return array<string, array{0: mixed}>
	 */
	public static function provide_bad_integers(): array {
		return [
			'below'    => [ 0 ],
			'above'    => [ 101 ],
			'fraction' => [ 1.5 ],
			'text'     => [ 'ten' ],
			'bool'     => [ true ],
			'empty'    => [ '' ],
			'exponent' => [ '1e2' ],
		];
	}

	public function test_normalises_an_enum_value(): void {
		$this->assertSame( 'redis', EnumParser::parse( ' Redis ', [ 'auto', 'redis' ] )->value() );
	}

	public function test_rejects_a_value_outside_the_enum(): void {
		$this->assertFalse( EnumParser::parse( 'memcached', [ 'auto', 'redis' ] )->is_valid() );
	}
}
