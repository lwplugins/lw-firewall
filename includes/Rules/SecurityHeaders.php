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
	 * The headers sent, name => value. The admin lists exactly these, so the
	 * screen can never promise a header that is not sent.
	 *
	 * @var array<string, string>
	 */
	public const HEADERS = [
		'X-Content-Type-Options' => 'nosniff',
		'X-Frame-Options'        => 'SAMEORIGIN',
		'Referrer-Policy'        => 'strict-origin-when-cross-origin',
		'Permissions-Policy'     => 'camera=(), microphone=(), geolocation=()',
	];

	/**
	 * Send security headers via WordPress send_headers action.
	 */
	public static function send(): void {
		if ( headers_sent() ) {
			return;
		}

		foreach ( self::HEADERS as $name => $value ) {
			header( $name . ': ' . $value );
		}
	}
}
