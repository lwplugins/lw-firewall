<?php
/**
 * Ban reason codes and their labels.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Bans;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Maps the reason codes recorded with a ban to what an administrator reads.
 *
 * Kept apart from BanTable because this list grows whenever a new rule can
 * issue a ban, which has nothing to do with how the table is laid out. A code
 * with no entry here still renders — bans issued before reasons were recorded
 * fall back to a neutral label rather than showing a raw slug.
 */
final class BanReasons {

	/**
	 * Label and secondary hint per reason code.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function all(): array {
		return [
			'login_lockout' => [
				__( 'Too many failed logins', 'lw-firewall' ),
				__( 'brute-force lockout', 'lw-firewall' ),
			],
			'reset_ip'      => [
				__( 'Password reset flood', 'lw-firewall' ),
				__( 'per-IP limit', 'lw-firewall' ),
			],
			'reset_spam'    => [
				__( 'Password reset bot request', 'lw-firewall' ),
				__( 'proof-of-render failed', 'lw-firewall' ),
			],
			'register_spam' => [
				__( 'Registration spam', 'lw-firewall' ),
				__( 'rejected sign-ups', 'lw-firewall' ),
			],
			'rate_limit'    => [
				__( 'Rate limit exceeded', 'lw-firewall' ),
				__( 'auto-ban escalation', 'lw-firewall' ),
			],
			'manual'        => [
				__( 'Banned by an administrator', 'lw-firewall' ),
				__( 'manual ban', 'lw-firewall' ),
			],
		];
	}

	/**
	 * Human label for a reason code.
	 *
	 * @param string $reason Reason code.
	 * @return string
	 */
	public static function label( string $reason ): string {
		$all = self::all();

		return $all[ $reason ][0] ?? __( 'Unknown', 'lw-firewall' );
	}

	/**
	 * Secondary line explaining what tripped.
	 *
	 * @param string $reason Reason code.
	 * @return string
	 */
	public static function hint( string $reason ): string {
		$all = self::all();

		return $all[ $reason ][1] ?? __( 'banned before reasons were recorded', 'lw-firewall' );
	}

	/**
	 * The subsystem that issued a ban with this reason.
	 *
	 * @param string $reason Reason code.
	 * @return string One of login, password_reset, registration, rate_limit, admin, unknown.
	 */
	public static function source( string $reason ): string {
		$sources = [
			'login_lockout' => 'login',
			'reset_ip'      => 'password_reset',
			'reset_spam'    => 'password_reset',
			'register_spam' => 'registration',
			'rate_limit'    => 'rate_limit',
			'manual'        => 'admin',
		];

		return $sources[ $reason ] ?? 'unknown';
	}
}
