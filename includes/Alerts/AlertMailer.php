<?php
/**
 * Administrator alert email delivery.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolves recipients and hands the alert to wp_mail().
 *
 * Wording lives in AlertMessage; this class only decides who gets the mail
 * and records whether delivery was accepted.
 */
final class AlertMailer {

	/**
	 * Transient recording the last wp_mail() failure, surfaced in the admin UI.
	 */
	public const ERROR_TRANSIENT = 'lw_firewall_admin_alert_mail_error';

	/**
	 * Resolve the configured recipients.
	 *
	 * Accepts a comma- or newline-separated list. Falls back to the site's
	 * admin_email so enabling the feature without filling the field still
	 * delivers somewhere useful — an alert nobody receives is worse than no
	 * alert at all, because it looks like protection.
	 *
	 * @return array<int, string>
	 */
	public static function recipients(): array {
		$raw   = (string) Options::get( 'admin_alert_email', '' );
		$parts = preg_split( '/[\r\n,;]+/', $raw );
		$clean = [];

		foreach ( is_array( $parts ) ? $parts : [] as $part ) {
			$email = sanitize_email( trim( (string) $part ) );

			if ( '' !== $email && is_email( $email ) ) {
				$clean[] = $email;
			}
		}

		if ( empty( $clean ) ) {
			$fallback = sanitize_email( (string) get_option( 'admin_email', '' ) );

			if ( '' !== $fallback && is_email( $fallback ) ) {
				$clean[] = $fallback;
			}
		}

		return array_values( array_unique( $clean ) );
	}

	/**
	 * Send one alert covering the given administrator accounts.
	 *
	 * @param array<int, int> $user_ids New administrator user IDs.
	 * @param string          $source   Detection source key.
	 * @return bool Whether the mail was handed off successfully.
	 */
	public static function notify( array $user_ids, string $source ): bool {
		$user_ids = AdminDetector::normalize( $user_ids );

		if ( empty( $user_ids ) ) {
			return false;
		}

		$to = self::recipients();

		if ( empty( $to ) ) {
			return false;
		}

		$sent = self::send(
			$to,
			AlertMessage::subject( $user_ids ),
			AlertMessage::body( $user_ids, $source )
		);

		if ( $sent ) {
			delete_transient( self::ERROR_TRANSIENT );
		} else {
			set_transient( self::ERROR_TRANSIENT, time(), WEEK_IN_SECONDS );
		}

		return $sent;
	}

	/**
	 * Send one alert covering identity changes on existing administrators.
	 *
	 * @param array<int, array{id: int, field: string, from: string, to: string}> $changes Detected changes.
	 * @param string                                                              $source  Detection source key.
	 * @return bool Whether the mail was handed off successfully.
	 */
	public static function notify_changes( array $changes, string $source ): bool {
		if ( empty( $changes ) ) {
			return false;
		}

		$to = self::recipients();

		if ( empty( $to ) ) {
			return false;
		}

		$sent = self::send(
			$to,
			ChangeMessage::subject( $changes ),
			ChangeMessage::body( $changes, $source )
		);

		if ( $sent ) {
			delete_transient( self::ERROR_TRANSIENT );
		} else {
			set_transient( self::ERROR_TRANSIENT, time(), WEEK_IN_SECONDS );
		}

		return $sent;
	}

	/**
	 * Send one alert about a password-reset flood.
	 *
	 * @param string $verdict Which limit was hit.
	 * @param string $ip      Requesting IP.
	 * @param int    $user_id Target account, or 0 when unknown.
	 * @return bool Whether the mail was handed off successfully.
	 */
	public static function notify_flood( string $verdict, string $ip, int $user_id ): bool {
		$to = self::recipients();

		if ( empty( $to ) ) {
			return false;
		}

		return self::send( $to, FloodMessage::subject(), FloodMessage::body( $verdict, $ip, $user_id ) );
	}

	/**
	 * Send a delivery test to the configured recipients.
	 *
	 * @return bool
	 */
	public static function send_test(): bool {
		$to = self::recipients();

		if ( empty( $to ) ) {
			return false;
		}

		return self::send( $to, AlertMessage::test_subject(), AlertMessage::test_body() );
	}

	/**
	 * Hand a plain-text message to wp_mail().
	 *
	 * @param array<int, string> $to      Recipients.
	 * @param string             $subject Subject line.
	 * @param string             $body    Message body.
	 * @return bool
	 */
	private static function send( array $to, string $subject, string $body ): bool {
		return (bool) wp_mail(
			$to,
			$subject,
			$body,
			[ 'Content-Type: text/plain; charset=UTF-8' ]
		);
	}
}
