<?php
/**
 * Declares the firewall's visitor cookies to LW Cookie.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Integrations;

use LightweightPlugins\Firewall\Rules\FilterCookie;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Lists the visitor cookies as strictly necessary, so LW Cookie never blocks
 * them and shows them under Necessary in the cookie declaration. Without LW
 * Cookie the filter is never applied.
 */
final class CookieDeclaration {

	/**
	 * Filter callback for `lw_cookie_known_cookies`.
	 *
	 * @param mixed $cookies Known cookies; an earlier callback may have returned something else.
	 * @return array<int, mixed>
	 */
	public static function register( $cookies ): array {
		if ( ! is_array( $cookies ) ) {
			$cookies = [];
		}

		$cookies[] = [
			'name'     => FilterCookie::COOKIE,
			'provider' => 'LW Firewall',
			'purpose'  => __( "Shows the site that the visitor's browser runs JavaScript, so product filters work during a bot flood.", 'lw-firewall' ),
			'duration' => __( '30 days', 'lw-firewall' ),
			'category' => 'necessary',
			'type'     => 'persistent',
		];
		$cookies[] = [
			'name'     => FilterCookie::MARKER,
			'provider' => 'LW Firewall',
			'purpose'  => __( 'Set for a moment while the bot check reloads the page, so the check never loops.', 'lw-firewall' ),
			'duration' => __( '1 minute', 'lw-firewall' ),
			'category' => 'necessary',
			'type'     => 'persistent',
		];

		return $cookies;
	}
}
