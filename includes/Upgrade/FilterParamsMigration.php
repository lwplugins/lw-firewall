<?php
/**
 * Retires the filter_params setting.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Upgrade;

use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rules\WooFilterParams;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Removes filter_params from the stored settings and remembers what is lost.
 *
 * Since 1.8.0 WooCommerce filter requests are recognised by WooCommerce's own
 * argument names (WooFilterParams), so the list is gone. Entries it covers
 * (filter_, query_type_, min_price…) keep their protection. Anything else an
 * operator had added (e.g. "add-to-cart|10") no longer has an equivalent; it
 * is kept in DROPPED_OPTION so the admin can be told once, instead of the
 * protection disappearing silently.
 */
final class FilterParamsMigration {

	/**
	 * Entries that were removed without a built-in replacement.
	 */
	public const DROPPED_OPTION = 'lw_firewall_dropped_filter_params';

	/**
	 * Run the migration when the retired key is still stored.
	 *
	 * Idempotent: once the key is gone the check is one lookup in the
	 * already-loaded (autoloaded) settings row.
	 *
	 * @return void
	 */
	public static function maybe_apply(): void {
		$saved = get_option( Options::OPTION_NAME, [] );

		if ( ! is_array( $saved ) || ! array_key_exists( 'filter_params', $saved ) ) {
			return;
		}

		$dropped = self::uncovered( $saved['filter_params'] );

		unset( $saved['filter_params'] );
		update_option( Options::OPTION_NAME, $saved );

		if ( [] !== $dropped ) {
			update_option( self::DROPPED_OPTION, $dropped, false );
		}
	}

	/**
	 * The entries of a stored list that the built-in recognition does not cover.
	 *
	 * @param mixed $entries Stored filter_params value (array, or legacy string).
	 * @return array<int, string>
	 */
	public static function uncovered( mixed $entries ): array {
		if ( is_string( $entries ) ) {
			$entries = preg_split( '/[\r\n,]+/', $entries );
		}

		$lost = [];

		foreach ( is_array( $entries ) ? $entries : [] as $entry ) {
			$entry = trim( (string) $entry );

			if ( '' !== $entry && ! WooFilterParams::covers_legacy_entry( $entry ) ) {
				$lost[] = $entry;
			}
		}

		return array_values( array_unique( $lost ) );
	}
}
