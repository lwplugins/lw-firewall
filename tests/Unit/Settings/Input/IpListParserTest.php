<?php
/**
 * Tests for the IP / CIDR list parser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings\Input;

use LightweightPlugins\Firewall\Settings\Input\IpListParser;

/**
 * @covers \LightweightPlugins\Firewall\Settings\Input\IpListParser
 */
final class IpListParserTest extends InputTestCase {

	public function test_keeps_valid_addresses_and_ranges_in_order(): void {
		$raw = "203.0.113.7\n10.0.0.0/8\n2001:db8::1\n2001:db8::/32";

		$this->assertSame(
			[ '203.0.113.7', '10.0.0.0/8', '2001:db8::1', '2001:db8::/32' ],
			IpListParser::parse( $raw )->value()
		);
	}

	/**
	 * Regression: invalid entries were stored and silently never matched.
	 *
	 * @dataProvider provide_invalid_entries
	 *
	 * @param string $entry Invalid entry.
	 */
	public function test_rejects_and_reports_an_invalid_entry( string $entry ): void {
		$result = IpListParser::parse( "203.0.113.7\n" . $entry );

		$this->assertFalse( $result->is_valid() );
		$this->assertStringContainsString( $entry, $result->errors()[0] );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_invalid_entries(): array {
		return [
			'hostname'         => [ 'example.com' ],
			'octet too big'    => [ '300.1.1.1' ],
			'v4 prefix > 32'   => [ '10.0.0.0/33' ],
			'v6 prefix > 128'  => [ '2001:db8::/129' ],
			'negative prefix'  => [ '10.0.0.0/-1' ],
			'text prefix'      => [ '10.0.0.0/foo' ],
			'empty prefix'     => [ '10.0.0.0/' ],
			'bare zero'        => [ '0' ],
			'two slashes'      => [ '10.0.0.0/8/9' ],
		];
	}

	/**
	 * Regression: array_filter() without a callback dropped a literal "0"
	 * line silently instead of reporting it.
	 */
	public function test_a_zero_line_is_reported_not_dropped(): void {
		$this->assertCount( 1, IpListParser::parse( "0\n1.2.3.4" )->errors() );
	}

	public function test_splits_on_commas_and_whitespace_too(): void {
		$this->assertSame( [ '1.2.3.4', '5.6.7.8', '9.9.9.9' ], IpListParser::parse( '1.2.3.4, 5.6.7.8 9.9.9.9' )->value() );
	}

	public function test_drops_duplicates(): void {
		$this->assertSame( [ '1.2.3.4' ], IpListParser::parse( [ '1.2.3.4', ' 1.2.3.4 ' ] )->value() );
	}

	public function test_an_empty_input_is_an_empty_list(): void {
		$this->assertSame( [], IpListParser::parse( "\n \n" )->value() );
	}

	public function test_rejects_nested_arrays(): void {
		$this->assertFalse( IpListParser::parse( [ [ '1.2.3.4' ] ] )->is_valid() );
	}
}
