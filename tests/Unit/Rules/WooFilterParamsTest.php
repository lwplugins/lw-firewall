<?php
/**
 * Tests for WooCommerce filter argument recognition.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\WooFilterParams;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\WooFilterParams
 */
final class WooFilterParamsTest extends TestCase {

	/**
	 * @dataProvider provide_names
	 *
	 * @param string $name     Argument name.
	 * @param bool   $expected Whether it is a filter argument.
	 */
	public function test_recognises_woocommerce_filter_arguments( string $name, bool $expected ): void {
		$this->assertSame( $expected, WooFilterParams::is_filter_arg( $name ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function provide_names(): array {
		return [
			'attribute'         => [ 'filter_hossz-mm', true ],
			'query type'        => [ 'query_type_atmero', true ],
			'stock status'      => [ 'filter_stock_status', true ],
			'min price'         => [ 'min_price', true ],
			'max price'         => [ 'max_price', true ],
			'rating'            => [ 'rating_filter', true ],
			'block categories'  => [ 'categories', true ],
			'block tags'        => [ 'tags', true ],
			'block brands'      => [ 'brands', true ],
			'upper case'        => [ 'FILTER_COLOR', true ],
			'bare prefix'       => [ 'filter_', false ],
			'orderby'           => [ 'orderby', false ],
			'paged'             => [ 'paged', false ],
			'prefix in middle'  => [ 'myfilter_x', false ],
		];
	}

	public function test_matches_when_any_argument_is_a_filter(): void {
		$this->assertTrue( WooFilterParams::matches( [ 'orderby' => 'price', 'filter_color' => 'red' ] ) );
	}

	public function test_does_not_match_without_filter_arguments(): void {
		$this->assertFalse( WooFilterParams::matches( [ 'orderby' => 'price', 'paged' => '2' ] ) );
	}

	/**
	 * @dataProvider provide_legacy_entries
	 *
	 * @param string $entry    Legacy filter_params entry.
	 * @param bool   $expected Whether the built-in recognition covers it.
	 */
	public function test_tells_which_legacy_entries_are_covered( string $entry, bool $expected ): void {
		$this->assertSame( $expected, WooFilterParams::covers_legacy_entry( $entry ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function provide_legacy_entries(): array {
		return [
			'default filter_'     => [ 'filter_|30', true ],
			'default query_type_' => [ 'query_type_|30', true ],
			'specific attribute'  => [ 'filter_color|5', true ],
			'price'               => [ 'min_price', true ],
			'add to cart'         => [ 'add-to-cart|10', false ],
			'unrelated'           => [ 's|20', false ],
		];
	}
}
