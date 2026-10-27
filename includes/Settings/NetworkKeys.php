<?php
/**
 * Settings that are network-wide on multisite (two-factor login).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * On multisite the auth cookie is valid on every site of the network, and a
 * user's second factors (user meta) are shared too, so a per-site two-factor
 * switch would leave a password-only way into the protected sites. Every
 * `twofa_*` key is therefore read from the main site, like the .htaccess geo
 * block that only the main site's settings shape (1.8.5), and only a network
 * administrator on the main site may change it.
 *
 * Single site: nothing changes.
 */
final class NetworkKeys {

	/**
	 * Prefix of the network-wide keys.
	 */
	public const PREFIX = 'twofa_';

	/**
	 * The main site's stored row, read once per request (subsites only).
	 *
	 * @var array<string, mixed>|null
	 */
	private static ?array $main = null;

	/**
	 * Whether a key is network-wide.
	 *
	 * @param string $key Option key.
	 */
	public static function is_network( string $key ): bool {
		return str_starts_with( $key, self::PREFIX );
	}

	/**
	 * Every network-wide key.
	 *
	 * @return array<int, string>
	 */
	public static function keys(): array {
		return array_values( array_filter( array_keys( Options::get_defaults() ), [ self::class, 'is_network' ] ) );
	}

	/**
	 * Whether this site reads the network-wide keys from the main site.
	 */
	public static function follows_main_site(): bool {
		return self::multisite() && ! is_main_site();
	}

	/**
	 * Whether the network-wide keys can be changed in this request: always on
	 * a single site; on multisite only on the main site, by a network
	 * administrator (or WP-CLI, which runs without a user).
	 */
	public static function editable(): bool {
		if ( ! self::multisite() ) {
			return true;
		}
		if ( ! is_main_site() ) {
			return false;
		}

		return ( defined( 'WP_CLI' ) && WP_CLI ) || current_user_can( 'manage_network_options' );
	}

	/**
	 * Network-wide keys that may not be written here (empty when editable()).
	 *
	 * @return array<int, string>
	 */
	public static function locked(): array {
		return self::editable() ? [] : self::keys();
	}

	/**
	 * Network-wide keys among submitted ones that may not be written here.
	 *
	 * @param array<string|int, mixed> $body Submitted key => value pairs.
	 * @return array<int, string>
	 */
	public static function refused( array $body ): array {
		$keys = array_map( 'strval', array_keys( $body ) );

		return array_values( array_intersect( $keys, self::locked() ) );
	}

	/**
	 * Why a network-wide key was refused.
	 */
	public static function message(): string {
		return __( 'Two-factor settings are network-wide: a network administrator sets them on the main site.', 'lw-firewall' );
	}

	/**
	 * Replace the network-wide keys with the main site's stored values on a
	 * subsite (callers layer the wp-config.php constants on top).
	 *
	 * @param array<string, mixed> $options Stored values of this site.
	 * @return array<string, mixed>
	 */
	public static function overlay( array $options ): array {
		if ( ! self::follows_main_site() ) {
			return $options;
		}

		$main = self::main_row();
		foreach ( self::keys() as $key ) {
			if ( array_key_exists( $key, $main ) ) {
				$options[ $key ] = $main[ $key ];
			}
		}

		return $options;
	}

	/**
	 * Forget the per-request copy of the main site's row (tests, saves).
	 */
	public static function flush(): void {
		self::$main = null;
	}

	/**
	 * Whether this is a multisite network. Options are read very early (the
	 * MU worker) and by plain-PHP tooling, so the core function may be absent.
	 */
	private static function multisite(): bool {
		return function_exists( 'is_multisite' ) && is_multisite();
	}

	/**
	 * The main site's stored row merged over the defaults.
	 *
	 * @return array<string, mixed>
	 */
	private static function main_row(): array {
		if ( null === self::$main ) {
			$saved      = get_blog_option( get_main_site_id(), Options::OPTION_NAME, [] );
			self::$main = array_merge( Options::get_defaults(), is_array( $saved ) ? $saved : [] );
		}

		return self::$main;
	}
}
