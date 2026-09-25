<?php
/**
 * Labels for the reason codes in the request log.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Logs;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The log stores raw codes (the worker writes them before WordPress is
 * loaded); the admin shows a translated label next to the code.
 */
final class LogReasons {

	/**
	 * Base code (without a trailing " (user N)") => label.
	 *
	 * @return array<string, string>
	 */
	public static function all(): array {
		return [
			'ip_blacklisted'      => __( 'Blacklisted IP', 'lw-firewall' ),
			'geo_blocked'         => __( 'Blocked country', 'lw-firewall' ),
			'auto_banned'         => __( 'Banned IP', 'lw-firewall' ),
			'bot_blocked'         => __( 'Blocked bot', 'lw-firewall' ),
			'rate_limited_404'    => __( '404 flood', 'lw-firewall' ),
			'rate_limited_login'  => __( 'Rate limit: wp-login.php', 'lw-firewall' ),
			'rate_limited_xmlrpc' => __( 'Rate limit: xmlrpc.php', 'lw-firewall' ),
			'rate_limited_cron'   => __( 'Rate limit: wp-cron.php', 'lw-firewall' ),
			'rate_limited_rest'   => __( 'Rate limit: REST API', 'lw-firewall' ),
			'rate_limited_filter' => __( 'Rate limit: filter parameters', 'lw-firewall' ),
			'login_lockout'       => __( 'Too many failed logins', 'lw-firewall' ),
			'login_user_lockout'  => __( 'Username locked after failed logins', 'lw-firewall' ),
			'register_spam'       => __( 'Registration spam', 'lw-firewall' ),
			'reset_ip'            => __( 'Password reset flood (per IP)', 'lw-firewall' ),
			'reset_user'          => __( 'Password reset flood (per account)', 'lw-firewall' ),
			'reset_global'        => __( 'Password reset flood (site-wide cap)', 'lw-firewall' ),
			'reset_spam'          => __( 'Password reset bot request', 'lw-firewall' ),
		];
	}

	/**
	 * The base code of a logged reason ("reset_user (user 7)" -> "reset_user").
	 *
	 * @param string $reason Logged reason.
	 * @return string
	 */
	public static function code( string $reason ): string {
		return (string) preg_replace( '/\s*\(.*\)\s*$/', '', trim( $reason ) );
	}

	/**
	 * The label for a logged reason; unknown codes are shown as they are.
	 *
	 * @param string $reason Logged reason.
	 * @return string
	 */
	public static function label( string $reason ): string {
		return self::all()[ self::code( $reason ) ] ?? $reason;
	}
}
