<?php
/**
 * Visitor cookie required for WooCommerce filter requests.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A filter URL is only served to a client that carries the visitor cookie.
 *
 * A distributed filter flood comes from thousands of addresses sending one
 * or two requests each, so no per-IP counter ever trips. What those clients
 * do not do is run the page's JavaScript. Every front-end page sets the cookie
 * from an inline script — not a Set-Cookie header, which a full-page cache
 * would either replay to everybody or refuse to cache — and a filter request
 * without it gets a tiny page that sets the cookie and reloads the same URL.
 */
final class FilterCookie {

	/**
	 * The visitor cookie.
	 */
	public const COOKIE = 'lwfw_v';

	/**
	 * Short-lived marker set by the challenge before it reloads, so a client
	 * whose cookie never reaches PHP (stripped by a proxy, a stale cached
	 * challenge) is shown a link instead of reloading forever.
	 */
	public const MARKER = 'lwfw_c';

	/**
	 * Cookie lifetime in seconds (30 days, renewed on every page view).
	 */
	private const MAX_AGE = 2592000;

	/**
	 * Whether the request carries the visitor cookie.
	 *
	 * @return bool
	 */
	public static function has_cookie(): bool {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared to a literal only.
		return isset( $_COOKIE[ self::COOKIE ] ) && '1' === $_COOKIE[ self::COOKIE ];
	}

	/**
	 * Whether the challenge may answer this request method.
	 *
	 * Only GET and HEAD: the challenge reloads with a GET, which would drop a
	 * POST body.
	 *
	 * @param string $method Request method.
	 * @return bool
	 */
	public static function applies_to_method( string $method ): bool {
		return in_array( strtoupper( $method ), [ 'GET', 'HEAD' ], true );
	}

	/**
	 * The script every front-end page carries: sets (renews) the cookie and
	 * clears the challenge marker.
	 *
	 * @return string JavaScript, without the script tag.
	 */
	public static function page_script(): string {
		return '(function(){var d=document,a="; path=/; SameSite=Lax"+(location.protocol==="https:"?"; Secure":"");'
			. 'd.cookie="' . self::COOKIE . '=1; max-age=' . self::MAX_AGE . '"+a;'
			. 'if(/(?:^|;\\s*)' . self::MARKER . '=/.test(d.cookie)){d.cookie="' . self::MARKER . '=; max-age=0"+a;}})();';
	}

	/**
	 * The challenge page.
	 *
	 * @param string                $fallback Local path of the same page without the filters.
	 * @param array<string, string> $text     Visible text: 'cookies', 'javascript', 'link', 'lang'.
	 * @return string
	 */
	public static function challenge_html( string $fallback, array $text = [] ): string {
		$text = array_map(
			static fn ( string $t ): string => htmlspecialchars( $t, ENT_QUOTES, 'UTF-8' ),
			array_merge( self::default_text(), $text )
		);
		$href = htmlspecialchars( $fallback, ENT_QUOTES, 'UTF-8' );
		$js   = '(function(){var d=document,a="; path=/; SameSite=Lax"+(location.protocol==="https:"?"; Secure":""),'
			. 'f=function(){d.getElementById("lwfw-f").hidden=false;};'
			. 'if(/(?:^|;\\s*)' . self::MARKER . '=1/.test(d.cookie)){f();return;}'
			. 'd.cookie="' . self::COOKIE . '=1; max-age=' . self::MAX_AGE . '"+a;'
			. 'd.cookie="' . self::MARKER . '=1; max-age=60"+a;'
			. 'if(!/(?:^|;\\s*)' . self::COOKIE . '=1/.test(d.cookie)){f();return;}'
			. 'location.replace(location.href);})();';

		return '<!DOCTYPE html><html lang="' . $text['lang'] . '"><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">'
			. '<meta name="viewport" content="width=device-width,initial-scale=1"><title>&#8230;</title></head>'
			. '<body style="font:16px/1.5 sans-serif;margin:2em">'
			. '<p id="lwfw-f" hidden>' . $text['cookies'] . ' <a href="' . $href . '">' . $text['link'] . '</a></p>'
			. '<noscript><p>' . $text['javascript'] . ' <a href="' . $href . '">' . $text['link'] . '</a></p></noscript>'
			. '<script>' . $js . '</script></body></html>';
	}

	/**
	 * The untranslated page text.
	 *
	 * @return array<string, string>
	 */
	private static function default_text(): array {
		return [
			'cookies'    => 'Filtering needs cookies enabled.',
			'javascript' => 'Filtering needs JavaScript.',
			'link'       => 'Continue without filters',
			'lang'       => 'en',
		];
	}

	/**
	 * The page text in the site's language.
	 *
	 * The worker answers at muplugins_loaded, before WordPress loads any
	 * plugin translation, so the plugin's own .mo (or the one in
	 * WP_LANG_DIR/plugins) is loaded here, only for a challenged request.
	 *
	 * @return array<string, string>
	 */
	private static function translated_text(): array {
		if ( ! function_exists( '__' ) || ! function_exists( 'determine_locale' ) ) {
			return self::default_text();
		}

		$locale = determine_locale();

		if ( ! is_textdomain_loaded( 'lw-firewall' ) ) {
			$global = defined( 'WP_LANG_DIR' ) ? WP_LANG_DIR . '/plugins/lw-firewall-' . $locale . '.mo' : '';

			if ( '' === $global || ! load_textdomain( 'lw-firewall', $global, $locale ) ) {
				load_textdomain( 'lw-firewall', dirname( __DIR__, 2 ) . '/languages/lw-firewall-' . $locale . '.mo', $locale );
			}
		}

		return [
			'cookies'    => __( 'Filtering needs cookies enabled.', 'lw-firewall' ),
			'javascript' => __( 'Filtering needs JavaScript.', 'lw-firewall' ),
			'link'       => __( 'Continue without filters', 'lw-firewall' ),
			'lang'       => str_replace( '_', '-', $locale ),
		];
	}

	/**
	 * Send the challenge and stop.
	 *
	 * 403, not 429: search engines read 429 as server overload and slow down
	 * crawling of the whole site, and neither status is stored by a page cache
	 * that caches 200s. no-store keeps any other cache out as well.
	 *
	 * @param string $request_uri Raw REQUEST_URI.
	 * @return void
	 */
	public static function challenge( string $request_uri ): void {
		if ( ! headers_sent() ) {
			header( 'HTTP/1.1 403 Forbidden' );
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'Cache-Control: no-store, private, max-age=0' );
			header( 'X-Robots-Tag: noindex, nofollow' );
		}

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Static page; the only variable part is escaped in challenge_html().
		echo self::challenge_html( RateLimiter::safe_redirect_path( $request_uri ), self::translated_text() );
		exit;
	}
}
