<?php
/**
 * Field definitions for the Spam settings tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provides the row definitions rendered by TabSpam. Kept separate so the tab
 * class stays a thin renderer and these arrays remain easy to scan/edit.
 */
final class SpamFields {

	/**
	 * Registration protection: enable toggle + token/honeypot tuning.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function registration(): array {
		return [
			'register_protect_enabled' => [
				'th'    => __( 'Enable Registration Protection', 'lw-firewall' ),
				'label' => __( 'Block bot registrations on wp-login.php?action=register', 'lw-firewall' ),
				'desc'  => __( 'Adds a signed proof-of-render token and honeypot to the registration form. Only active when "Anyone can register" is enabled.', 'lw-firewall' ),
			],
			'register_honeypot'        => [
				'th'    => __( 'Honeypot', 'lw-firewall' ),
				'label' => __( 'Add a hidden honeypot field', 'lw-firewall' ),
				'desc'  => __( 'Catches generic bots that fill every field. Invisible to real users.', 'lw-firewall' ),
			],
			'register_single_use'      => [
				'th'    => __( 'Single-Use Token', 'lw-firewall' ),
				'label' => __( 'Reject reused tokens', 'lw-firewall' ),
				'desc'  => __( 'Stores used tokens in the firewall storage backend so each rendered form can register only once.', 'lw-firewall' ),
			],
			'register_min_fill_time'   => [
				'type' => 'number',
				'th'   => __( 'Minimum Fill Time', 'lw-firewall' ),
				'min'  => 1,
				'max'  => 60,
				'desc' => __( 'Reject submissions faster than this many seconds after the form loaded (catches instant bot POSTs).', 'lw-firewall' ),
			],
			'register_token_max_age'   => [
				'type' => 'number',
				'th'   => __( 'Token Lifetime', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'How long a rendered form stays valid, in seconds (3600 = 1 hour).', 'lw-firewall' ),
			],
		];
	}

	/**
	 * Registration auto-ban: threshold + duration.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function auto_ban(): array {
		return [
			'register_ban_threshold' => [
				'type' => 'number',
				'th'   => __( 'Ban Threshold', 'lw-firewall' ),
				'min'  => 2,
				'max'  => 100,
				'desc' => __( 'Number of rejected registrations from one IP before it is banned.', 'lw-firewall' ),
			],
			'register_ban_duration'  => [
				'type' => 'number',
				'th'   => __( 'Ban Duration', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'How long the ban lasts in seconds (3600 = 1 hour).', 'lw-firewall' ),
			],
		];
	}
}
