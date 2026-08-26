<?php
/**
 * Field definitions for the password-reset sections of the Spam tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Row definitions rendered by TabSpam for password-reset flood protection.
 * Kept separate from SpamFields so registration and reset settings stay
 * independently editable.
 */
final class ResetFields {

	/**
	 * Master toggle and the three rate-limit axes.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function limits(): array {
		return [
			'reset_protect_enabled' => [
				'th'    => __( 'Enable Reset Protection', 'lw-firewall' ),
				'label' => __( 'Rate limit password reset requests', 'lw-firewall' ),
				'desc'  => __( 'Covers wp-login.php?action=lostpassword and the WooCommerce "Lost your password?" form — both go through the same WordPress hook. Requests started by an administrator or by WP-CLI are never limited.', 'lw-firewall' ),
			],
			'reset_ip_max'          => [
				'type' => 'number',
				'th'   => __( 'Requests per IP', 'lw-firewall' ),
				'min'  => 0,
				'max'  => 1000,
				'desc' => __( 'How many reset requests one IP address may make per window. 0 disables this limit.', 'lw-firewall' ),
			],
			'reset_ip_window'       => [
				'type' => 'number',
				'th'   => __( 'Per-IP Window', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'Length of the per-IP window in seconds (900 = 15 minutes).', 'lw-firewall' ),
			],
			'reset_user_max'        => [
				'type' => 'number',
				'th'   => __( 'Requests per Account', 'lw-firewall' ),
				'min'  => 0,
				'max'  => 1000,
				'desc' => __( 'How many reset emails one account may receive per window, no matter how many different IPs ask. This is the only limit that stops a distributed flood of one person\'s inbox. 0 disables it.', 'lw-firewall' ),
			],
			'reset_user_window'     => [
				'type' => 'number',
				'th'   => __( 'Per-Account Window', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'Length of the per-account window in seconds (3600 = 1 hour).', 'lw-firewall' ),
			],
			'reset_global_max'      => [
				'type' => 'number',
				'th'   => __( 'Site-Wide Hourly Cap', 'lw-firewall' ),
				'min'  => 0,
				'max'  => 10000,
				'desc' => __( 'Total reset emails the site will send in an hour. Protects your hosting mail quota and stops your domain being flagged as a spam source. 0 disables it.', 'lw-firewall' ),
			],
		];
	}

	/**
	 * Bot filtering, banning, alerting and admin hardening.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function hardening(): array {
		return [
			'reset_proof_enabled' => [
				'th'    => __( 'Proof of Render', 'lw-firewall' ),
				'label' => __( 'Require a signed token and honeypot on the wp-login form', 'lw-firewall' ),
				'desc'  => __( 'Rejects direct POSTs that never loaded the form. Only enforced on wp-login.php, since other lost-password forms (WooCommerce, custom login pages) do not render the token. Turn this off if a login plugin replaces the wp-login form.', 'lw-firewall' ),
			],
			'reset_min_fill_time' => [
				'type' => 'number',
				'th'   => __( 'Minimum Fill Time', 'lw-firewall' ),
				'min'  => 1,
				'max'  => 60,
				'desc' => __( 'Reject submissions faster than this many seconds after the form loaded. Separate from the registration setting, so the two forms can be tuned independently.', 'lw-firewall' ),
			],
			'reset_token_max_age' => [
				'type' => 'number',
				'th'   => __( 'Token Lifetime', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'How long a rendered lost-password form stays valid, in seconds (3600 = 1 hour).', 'lw-firewall' ),
			],
			'reset_single_use'    => [
				'th'    => __( 'Single-Use Token', 'lw-firewall' ),
				'label' => __( 'Reject reused tokens', 'lw-firewall' ),
				'desc'  => __( 'Each rendered form may submit one reset request. Without this, a bot can load the form once and replay that token for the whole token lifetime.', 'lw-firewall' ),
			],
			'reset_auto_ban'      => [
				'th'    => __( 'Auto-Ban', 'lw-firewall' ),
				'label' => __( 'Ban IPs that trip the per-IP limit or fail the token check', 'lw-firewall' ),
				'desc'  => __( 'A banned IP is blocked from the whole site by the MU-plugin worker. Account and site-wide limits never ban: they say nothing about who happened to ask last.', 'lw-firewall' ),
			],
			'reset_ban_duration'  => [
				'type' => 'number',
				'th'   => __( 'Ban Duration', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'How long the ban lasts in seconds (3600 = 1 hour).', 'lw-firewall' ),
			],
			'reset_alert_enabled' => [
				'th'    => __( 'Email Alert', 'lw-firewall' ),
				'label' => __( 'Email me when a reset limit is reached', 'lw-firewall' ),
				'desc'  => __( 'Sends at most one message per limit per hour, to the recipients configured on the Alerts tab.', 'lw-firewall' ),
			],
			'reset_block_admins'  => [
				'th'    => __( 'Block Admin Resets', 'lw-firewall' ),
				'label' => __( 'Never allow password reset for administrator accounts', 'lw-firewall' ),
				'desc'  => __( 'Closes the "flood the admin inbox, then phish the reset link" path entirely. A locked-out administrator can then only be recovered by WP-CLI or by another administrator, so leave this off unless you have that access.', 'lw-firewall' ),
			],
		];
	}
}
