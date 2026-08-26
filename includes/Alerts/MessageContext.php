<?php
/**
 * Shared alert email context lines.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

use LightweightPlugins\Firewall\IpDetector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds the header and "who did it" lines every alert email shares.
 */
final class MessageContext {

	/**
	 * The site name, decoded for plain-text output.
	 *
	 * @return string
	 */
	public static function site_name(): string {
		return wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
	}

	/**
	 * Site, URL, timestamp and detection-source lines.
	 *
	 * @param string $source Detection source key.
	 * @return array<int, string>
	 */
	public static function header_lines( string $source ): array {
		return [
			/* translators: %s: site name. */
			sprintf( __( 'Site: %s', 'lw-firewall' ), self::site_name() ),
			/* translators: %s: site URL. */
			sprintf( __( 'URL: %s', 'lw-firewall' ), home_url( '/' ) ),
			/* translators: %s: local date and time. */
			sprintf( __( 'Detected: %s', 'lw-firewall' ), current_time( 'mysql' ) ),
			/* translators: %s: how the change was detected. */
			sprintf( __( 'Detected via: %s', 'lw-firewall' ), self::source_label( $source ) ),
		];
	}

	/**
	 * Extra "who did it" context, available only for in-request detections.
	 *
	 * @param string $source Detection source key.
	 * @return array<int, string>
	 */
	public static function actor_lines( string $source ): array {
		if ( 'scan' === $source ) {
			return [
				'',
				__( 'WARNING: this was found by a database scan, not by a WordPress hook. It most likely happened outside the normal WordPress flow — a direct database write, a plugin bypassing core APIs, or while LW Firewall was inactive.', 'lw-firewall' ),
			];
		}

		$lines    = [];
		$actor    = wp_get_current_user();
		$actor_id = (int) $actor->ID;

		if ( $actor_id > 0 ) {
			$lines[] = sprintf(
				/* translators: 1: username of the acting user, 2: user ID. */
				__( 'Performed by: %1$s (ID %2$d)', 'lw-firewall' ),
				(string) $actor->user_login,
				$actor_id
			);
		} else {
			$lines[] = __( 'Performed by: no logged-in user (WP-CLI, cron or unauthenticated request)', 'lw-firewall' );
		}

		$ip = IpDetector::get_ip();

		if ( '' !== $ip ) {
			/* translators: %s: IP address. */
			$lines[] = sprintf( __( 'Request IP: %s', 'lw-firewall' ), $ip );
		}

		return $lines;
	}

	/**
	 * The closing advice and signature block.
	 *
	 * @param string $advice Situation-specific first line.
	 * @return array<int, string>
	 */
	public static function footer_lines( string $advice ): array {
		return [
			'',
			'----------------------------------------',
			$advice,
			'',
			__( 'Sent by LW Firewall.', 'lw-firewall' ),
		];
	}

	/**
	 * Human label for a detection source key.
	 *
	 * @param string $source Detection source key.
	 * @return string
	 */
	public static function source_label( string $source ): string {
		$labels = [
			'user_register'       => __( 'new user registration', 'lw-firewall' ),
			'set_user_role'       => __( 'role assignment (set_user_role)', 'lw-firewall' ),
			'add_user_role'       => __( 'role addition (add_user_role)', 'lw-firewall' ),
			'granted_super_admin' => __( 'super admin grant', 'lw-firewall' ),
			'add_user_to_blog'    => __( 'user added to site', 'lw-firewall' ),
			'profile_update'      => __( 'profile update', 'lw-firewall' ),
			'wp_set_password'     => __( 'password change or reset', 'lw-firewall' ),
			'scan'                => __( 'scheduled database scan', 'lw-firewall' ),
			'reset_flood'         => __( 'password reset rate limit', 'lw-firewall' ),
		];

		return $labels[ $source ] ?? $source;
	}
}
