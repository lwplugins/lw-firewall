<?php
/**
 * Bot User-Agent blocking.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Blocks requests from known bot User-Agent strings.
 */
final class BotBlocker {

	/**
	 * Check if the given User-Agent should be blocked.
	 *
	 * @param string $user_agent The HTTP User-Agent header value.
	 * @return bool
	 */
	public static function is_blocked( string $user_agent ): bool {
		if ( '' === $user_agent ) {
			return false;
		}

		$ua_lower     = strtolower( $user_agent );
		$blocked_bots = Options::get( 'blocked_bots' );

		if ( ! is_array( $blocked_bots ) ) {
			return false;
		}

		foreach ( $blocked_bots as $bot ) {
			if ( str_contains( $ua_lower, strtolower( (string) $bot ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Send a 403 response and exit.
	 */
	public static function block(): void {
		if ( ! headers_sent() ) {
			header( 'HTTP/1.1 403 Forbidden' );
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'Cache-Control: no-store, no-cache' );
		}

		echo 'Access denied.';
		exit;
	}
}
