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
	 * Call after any change to geo_enabled or blocked_countries.
	 */
	public static function sync(): void {
		$options   = Options::get_all();
		$enabled   = ! empty( $options['geo_enabled'] );
		$countries = (array) ( $options['blocked_countries'] ?? [] );

		self::write( $enabled, $countries );
	}

	/**
	 * Remove geo rules from .htaccess.
	 */
	public static function remove(): void {
		self::write( false, [] );
	}

	/**
	 * Write or clear geo blocking rules in .htaccess.
	 *
	 * @param bool     $enabled   Whether geo blocking is active.
	 * @param string[] $countries Blocked country codes.
	 */
	private static function write( bool $enabled, array $countries ): void {
		$path = self::get_htaccess_path();

		if ( ! file_exists( $path ) ) {
			return;
		}

		insert_with_markers( $path, self::MARKER, self::build_rules( $enabled, $countries ) );
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
