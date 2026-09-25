<?php
/**
 * Htaccess writer for Geo Blocking.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Geo;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Writes CF-IPCountry based RewriteRules to .htaccess.
 */
final class HtaccessWriter {

	/**
	 * Marker name for insert_with_markers().
	 */
	private const MARKER = 'LW Firewall Geo';

	/**
	 * Sync .htaccess with current geo blocking settings.
	 *
	 * Call after any change to enabled, geo_enabled or blocked_countries.
	 */
	public static function sync(): void {
		self::write( self::rules_for( Options::get_all() ) );
	}

	/**
	 * The rule lines the given effective settings call for.
	 *
	 * Empty (which removes the block) unless geo blocking is active — the
	 * master switch included: with the firewall switched off, Apache must not
	 * go on refusing visitors of the listed countries.
	 *
	 * @param array<string, mixed> $options Effective settings.
	 * @return array<int, string>
	 */
	public static function rules_for( array $options ): array {
		return self::build_rules(
			GeoActivation::is_active( $options ),
			(array) ( $options['blocked_countries'] ?? [] )
		);
	}

	/**
	 * Remove geo rules from .htaccess.
	 */
	public static function remove(): void {
		self::write( [] );
	}

	/**
	 * Write (or, with no lines, clear) the geo block in .htaccess.
	 *
	 * @param array<int, string> $lines Rule lines.
	 */
	private static function write( array $lines ): void {
		$path = self::get_htaccess_path();

		if ( ! file_exists( $path ) ) {
			return;
		}

		// insert_with_markers() lives in an admin include; sync() also runs on
		// front-end requests (right after an update) and under WP-CLI.
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}

		insert_with_markers( $path, self::MARKER, $lines );
	}

	/**
	 * Build the .htaccess rule lines for the given geo settings.
	 *
	 * Country codes are validated down to `^[A-Z]{2}$` before being embedded in
	 * the RewriteCond, so an attacker-influenced value (e.g. one carrying a
	 * newline, imported from an untrusted settings JSON) cannot inject arbitrary
	 * Apache directives via insert_with_markers().
	 *
	 * @param bool                     $enabled   Whether geo blocking is active.
	 * @param array<int|string, mixed> $countries Raw blocked country codes.
	 * @return array<int, string>
	 */
	public static function build_rules( bool $enabled, array $countries ): array {
		$countries = Options::sanitize_country_codes( $countries );

		if ( ! $enabled || empty( $countries ) ) {
			return [];
		}

		$pattern = implode( '|', $countries );

		return [
			'RewriteCond %{HTTP:CF-IPCountry} ^(' . $pattern . ')$ [NC]',
			'RewriteRule .* - [F,L]',
		];
	}

	/**
	 * Get .htaccess file path.
	 *
	 * @return string
	 */
	private static function get_htaccess_path(): string {
		return ABSPATH . '.htaccess';
	}
}
