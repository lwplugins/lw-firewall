<?php
/**
 * Security response headers.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds security-related HTTP response headers.
 */
final class SecurityHeaders {

	/**
	 * Send security headers via WordPress send_headers action.
	 */
	public static function send(): void {
		if ( headers_sent() ) {
			return;
		}

		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
		header( 'X-XSS-Protection: 1; mode=block' );
	}
}
