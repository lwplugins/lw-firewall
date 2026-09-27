<?php
/**
 * Visible text of the cookie challenge page.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The challenge page's words, per kind of request, in the site's language.
 *
 * The worker answers at muplugins_loaded, before WordPress loads any plugin
 * translation, so the plugin's own .mo (or the one in WP_LANG_DIR/plugins) is
 * loaded here, and only for a challenged request.
 */
final class ChallengeText {

	/**
	 * Challenge for a WooCommerce filter URL.
	 */
	public const FILTER = 'filter';

	/**
	 * Challenge for a ?add-to-cart= link.
	 */
	public const CART = 'cart';

	/**
	 * The untranslated text.
	 *
	 * @param string $kind self::FILTER or self::CART.
	 * @return array<string, string> Keys: cookies, javascript, link, lang.
	 */
	public static function defaults( string $kind ): array {
		if ( self::CART === $kind ) {
			return [
				'cookies'    => 'Adding to the cart needs cookies enabled.',
				'javascript' => 'Adding to the cart needs JavaScript.',
				'link'       => 'Continue without adding to the cart',
				'lang'       => 'en',
			];
		}

		return [
			'cookies'    => 'Filtering needs cookies enabled.',
			'javascript' => 'Filtering needs JavaScript.',
			'link'       => 'Continue without filters',
			'lang'       => 'en',
		];
	}

	/**
	 * The text in the site's language.
	 *
	 * @param string $kind self::FILTER or self::CART.
	 * @return array<string, string>
	 */
	public static function translated( string $kind ): array {
		if ( ! function_exists( '__' ) || ! function_exists( 'determine_locale' ) ) {
			return self::defaults( $kind );
		}

		$locale = determine_locale();
		self::load_textdomain( $locale );

		if ( self::CART === $kind ) {
			$text = [
				'cookies'    => __( 'Adding to the cart needs cookies enabled.', 'lw-firewall' ),
				'javascript' => __( 'Adding to the cart needs JavaScript.', 'lw-firewall' ),
				'link'       => __( 'Continue without adding to the cart', 'lw-firewall' ),
			];
		} else {
			$text = [
				'cookies'    => __( 'Filtering needs cookies enabled.', 'lw-firewall' ),
				'javascript' => __( 'Filtering needs JavaScript.', 'lw-firewall' ),
				'link'       => __( 'Continue without filters', 'lw-firewall' ),
			];
		}

		$text['lang'] = str_replace( '_', '-', $locale );

		return $text;
	}

	/**
	 * Load the plugin's translations for a locale, if not loaded yet.
	 *
	 * @param string $locale Locale.
	 * @return void
	 */
	private static function load_textdomain( string $locale ): void {
		if ( is_textdomain_loaded( 'lw-firewall' ) ) {
			return;
		}

		$global = defined( 'WP_LANG_DIR' ) ? WP_LANG_DIR . '/plugins/lw-firewall-' . $locale . '.mo' : '';

		if ( '' === $global || ! load_textdomain( 'lw-firewall', $global, $locale ) ) {
			load_textdomain( 'lw-firewall', dirname( __DIR__, 2 ) . '/languages/lw-firewall-' . $locale . '.mo', $locale );
		}
	}
}
