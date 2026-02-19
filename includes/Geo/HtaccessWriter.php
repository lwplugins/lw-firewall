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

		$rules = [];

		if ( $enabled && ! empty( $countries ) ) {
			$pattern = implode( '|', array_map( 'strtoupper', $countries ) );
			$rules   = [
				'RewriteCond %{HTTP:CF-IPCountry} ^(' . $pattern . ')$ [NC]',
				'RewriteRule .* - [F,L]',
			];
		}

		insert_with_markers( $path, self::MARKER, $rules );
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
