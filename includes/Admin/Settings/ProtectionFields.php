<?php
/**
 * Field definitions for the Protection settings tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provides the row definitions rendered by TabProtection. Kept separate so the
 * tab class stays a thin renderer and these arrays remain easy to scan/edit.
 */
final class ProtectionFields {

	/**
	 * Endpoint rate-limit toggles.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function endpoints(): array {
		return [
			'protect_cron'     => [
				'label' => __( 'Rate-limit wp-cron.php requests', 'lw-firewall' ),
				'desc'  => __( 'Protects against DDoS attacks targeting wp-cron.php.', 'lw-firewall' ),
			],
			'protect_xmlrpc'   => [
				'label' => __( 'Rate-limit xmlrpc.php requests', 'lw-firewall' ),
				'desc'  => __( 'Protects against brute-force and DDoS via xmlrpc.php.', 'lw-firewall' ),
			],
			'protect_login'    => [
				'label' => __( 'Rate-limit wp-login.php requests', 'lw-firewall' ),
				'desc'  => __( 'Rate-limits wp-login.php requests per IP.', 'lw-firewall' ),
			],
			'protect_rest_api' => [
				'label' => __( 'Rate-limit REST API requests', 'lw-firewall' ),
				'desc'  => __( 'Rate-limits /wp-json/ requests per IP.', 'lw-firewall' ),
			],
			'protect_404'      => [
				'label' => __( 'Block 404 flood', 'lw-firewall' ),
				'desc'  => __( 'Blocks IPs that generate excessive 404 errors (vulnerability scanning).', 'lw-firewall' ),
			],
		];
	}

	/**
	 * Brute-force login protection: enable toggle + thresholds.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function login_protection(): array {
		return [
			'login_limit_enabled'    => [
				'th'    => __( 'Enable Login Protection', 'lw-firewall' ),
				'label' => __( 'Ban IPs after repeated failed logins', 'lw-firewall' ),
				'desc'  => __( 'Counts failed password attempts per IP via wp_login_failed.', 'lw-firewall' ),
			],
			'login_max_attempts'     => [
				'type' => 'number',
				'th'   => __( 'Failed Attempts', 'lw-firewall' ),
				'min'  => 2,
				'max'  => 100,
				'desc' => __( 'Number of failed login attempts before the IP is banned.', 'lw-firewall' ),
			],
			'login_lockout_window'   => [
				'type' => 'number',
				'th'   => __( 'Detection Window', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'Seconds within which failed attempts are counted (600 = 10 minutes).', 'lw-firewall' ),
			],
			'login_lockout_duration' => [
				'type' => 'number',
				'th'   => __( 'Ban Duration', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'How long the ban lasts in seconds (3600 = 1 hour).', 'lw-firewall' ),
			],
		];
	}

	/**
	 * Auto-ban: enable toggle + threshold/duration.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function auto_ban(): array {
		return [
			'auto_ban_enabled'   => [
				'th'    => __( 'Enable Auto-Ban', 'lw-firewall' ),
				'label' => __( 'Ban IPs after repeated violations', 'lw-firewall' ),
				'desc'  => __( 'After the threshold is reached, the IP is banned for the configured duration.', 'lw-firewall' ),
			],
			'auto_ban_threshold' => [
				'type' => 'number',
				'th'   => __( 'Ban Threshold', 'lw-firewall' ),
				'min'  => 2,
				'max'  => 100,
				'desc' => __( 'Number of rate-limit violations before an IP is banned.', 'lw-firewall' ),
			],
			'auto_ban_duration'  => [
				'type' => 'number',
				'th'   => __( 'Ban Duration', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'How long the ban lasts in seconds (3600 = 1 hour).', 'lw-firewall' ),
			],
		];
	}
}
