<?php
/**
 * WooCommerce product-filter query parameter recognition.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Recognises the query arguments WooCommerce product filtering uses.
 *
 * Built in rather than configurable: the filter_params list it replaces only
 * protected what an operator remembered to list, and emptying it silently
 * switched filter protection off. Checked against WooCommerce 11.1.2:
 * - classic layered-nav widgets (WC_Query, the widgets): filter_{attribute},
 *   query_type_{attribute}, min_price, max_price, rating_filter;
 * - the block Product Filters (src/Internal/ProductFilters/Params.php): the
 *   same, plus filter_stock_status, filter_{taxonomy} for custom product
 *   taxonomies and the short names categories, tags and brands.
 */
final class WooFilterParams {

	/**
	 * Argument-name prefixes.
	 *
	 * @var array<int, string>
	 */
	private const PREFIXES = [ 'filter_', 'query_type_' ];

	/**
	 * Exact argument names.
	 *
	 * @var array<int, string>
	 */
	private const NAMES = [ 'min_price', 'max_price', 'rating_filter', 'categories', 'tags', 'brands' ];

	/**
	 * Whether any of the query arguments is a WooCommerce filter argument.
	 *
	 * @param array<string, string> $args Parsed query arguments.
	 * @return bool
	 */
	public static function matches( array $args ): bool {
		foreach ( array_keys( $args ) as $name ) {
			if ( self::is_filter_arg( (string) $name ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether one argument name is a WooCommerce filter argument.
	 *
	 * @param string $name Argument name.
	 * @return bool
	 */
	public static function is_filter_arg( string $name ): bool {
		$name = strtolower( $name );

		if ( in_array( $name, self::NAMES, true ) ) {
			return true;
		}

		foreach ( self::PREFIXES as $prefix ) {
			if ( str_starts_with( $name, $prefix ) && strlen( $name ) > strlen( $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a filter_params entry ("prefix|limit") is covered by the
	 * built-in recognition. Used by the upgrade that retires that list.
	 *
	 * @param string $entry Legacy filter_params entry.
	 * @return bool
	 */
	public static function covers_legacy_entry( string $entry ): bool {
		$prefix = strtolower( trim( explode( '|', $entry, 2 )[0] ) );

		return in_array( $prefix, self::PREFIXES, true ) || self::is_filter_arg( $prefix );
	}
}
