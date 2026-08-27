<?php
/**
 * Consequences of a refused password-reset request.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Alerts\AlertMailer;
use LightweightPlugins\Firewall\Logger;
use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * What happens once PasswordResetGuard has decided to refuse a request:
 * the log entry, the optional IP ban, the throttled alert, and the message
 * shown to whoever asked.
 *
 * Split out from the guard so the "should this be refused?" decision and the
 * "what do we do about it" response change independently.
 */
final class ResetPenalty {

	/**
	 * Storage key prefix for the alert throttle.
	 */
	private const ALERT_KEY = 'reset_alert_sent';

	/**
	 * Apply every configured consequence of a refusal.
	 *
	 * @param string $verdict Refusal reason.
	 * @param string $ip      Requesting IP.
	 * @param int    $user_id Target account, or 0 when unknown.
	 * @return void
	 */
	public static function apply( string $verdict, string $ip, int $user_id ): void {
		self::log( $verdict, $ip, $user_id );
		self::maybe_ban( $verdict, $ip );
		self::maybe_alert( $verdict, $ip, $user_id );
	}

	/**
	 * The message shown to the requester.
	 *
	 * Deliberately the same for every rate-limit verdict: telling a flooder
	 * which limit they hit tells them how to pace around it.
	 *
	 * @param string $verdict Refusal reason.
	 * @return string
	 */
	public static function message( string $verdict ): string {
		if ( PasswordResetGuard::SPAM === $verdict ) {
			return __( '<strong>Error:</strong> Password reset failed, please try again.', 'lw-firewall' );
		}

		return __( '<strong>Error:</strong> Too many password reset requests. Please try again later.', 'lw-firewall' );
	}

	/**
	 * Write a firewall log entry.
	 *
	 * @param string $verdict Refusal reason.
	 * @param string $ip      Requesting IP.
	 * @param int    $user_id Target account, or 0 when unknown.
	 * @return void
	 */
	private static function log( string $verdict, string $ip, int $user_id ): void {
		if ( empty( Options::get( 'log_enabled' ) ) ) {
			return;
		}

		$reason = 'reset_' . $verdict;

		if ( $user_id > 0 ) {
			$reason .= ' (user ' . $user_id . ')';
		}

		Logger::log(
			[
				'ip'     => $ip,
				'reason' => $reason,
				'ua'     => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 ),
				'url'    => sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ),
			]
		);
	}

	/**
	 * Ban the requesting IP when the verdict is about the requester.
	 *
	 * A target or site-wide limit says nothing about who asked — banning them
	 * would punish whoever happened to submit last, which on a distributed
	 * flood is as likely to be the real user as the attacker.
	 *
	 * @param string $verdict Refusal reason.
	 * @param string $ip      Requesting IP.
	 * @return void
	 */
	private static function maybe_ban( string $verdict, string $ip ): void {
		if ( empty( Options::get( 'reset_auto_ban' ) ) || '' === $ip ) {
			return;
		}

		if ( ! in_array( $verdict, [ ResetLimiter::IP, PasswordResetGuard::SPAM ], true ) ) {
			return;
		}

		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );

		( new AutoBanner( $storage ) )->ban( $ip, (int) Options::get( 'reset_ban_duration', 3600 ), 'reset_' . $verdict );
	}

	/**
	 * Email the alert recipients at most once per hour per verdict.
	 *
	 * @param string $verdict Refusal reason.
	 * @param string $ip      Requesting IP.
	 * @param int    $user_id Target account, or 0 when unknown.
	 * @return void
	 */
	private static function maybe_alert( string $verdict, string $ip, int $user_id ): void {
		if ( empty( Options::get( 'reset_alert_enabled' ) ) ) {
			return;
		}

		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );

		// One notice per verdict per hour: an alert that arrives once per
		// blocked request is itself the flood it is reporting.
		if ( $storage->increment( self::ALERT_KEY . '_' . $verdict, HOUR_IN_SECONDS ) > 1 ) {
			return;
		}

		AlertMailer::notify_flood( $verdict, $ip, $user_id );
	}
}
