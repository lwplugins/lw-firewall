<?php
/**
 * Honest outcomes for the alert actions.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Alerts;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Maps a scan or a test send to what actually happened: no "clean" when
 * alerts are off, no "email sent" when the mail was queued.
 */
final class AlertOutcome {

	/**
	 * Outcome of a scan.
	 *
	 * @param array{new: array<int, int>, changes: array<int, mixed>, disabled: bool, seeded: bool, sent: bool, queued: bool} $scan AdminScanner::run() result.
	 * @return array{state: string, sent: bool, queued: bool, message: string}
	 */
	public static function scan( array $scan ): array {
		if ( $scan['disabled'] ) {
			return self::shape( 'disabled', false, false, __( 'Administrator alerts are switched off, so nothing was scanned. Turn them on and save first.', 'lw-firewall' ) );
		}

		$found = [] !== $scan['new'] || [] !== $scan['changes'];

		if ( ! $found ) {
			return self::shape( 'clean', $scan['sent'], $scan['queued'], self::clean_message( $scan ) );
		}

		$message = $scan['queued']
			? __( 'Scan finished: new or modified administrators were found, but the alert email could not be sent. It is queued and will be retried on the next scan.', 'lw-firewall' )
			: __( 'Scan finished: new or modified administrators were found and an alert email was sent.', 'lw-firewall' );

		return self::shape( 'found', $scan['sent'], $scan['queued'], $message );
	}

	/**
	 * Outcome of a test send.
	 *
	 * @param bool $has_recipients Whether any valid recipient exists.
	 * @param bool $sent           Whether wp_mail() accepted the message.
	 * @return array{sent: bool, queued: bool, error: string|null, message: string}
	 */
	public static function test( bool $has_recipients, bool $sent ): array {
		if ( ! $has_recipients ) {
			$error = __( 'There is no valid recipient: set a notification email, or a valid site admin email under Settings → General.', 'lw-firewall' );
		} elseif ( ! $sent ) {
			$error = __( 'The test alert could not be sent — wp_mail() refused it. Check your SMTP plugin or hosting mail limits.', 'lw-firewall' );
		} else {
			$error = null;
		}

		return [
			'sent'    => null === $error,
			'queued'  => false,
			'error'   => $error,
			'message' => null === $error
				? __( 'Test alert sent. If it does not arrive, the problem is your site mail configuration, not the firewall.', 'lw-firewall' )
				: $error,
		];
	}

	/**
	 * Message for a scan that found nothing new.
	 *
	 * @param array{seeded: bool, sent: bool, queued: bool} $scan Scan flags.
	 * @return string
	 */
	private static function clean_message( array $scan ): string {
		if ( $scan['seeded'] ) {
			return __( 'No snapshot existed yet, so the current administrators were recorded silently. Later changes will be reported.', 'lw-firewall' );
		}

		if ( $scan['queued'] ) {
			return __( 'Scan finished: no new or modified administrators. Earlier alerts still could not be sent and stay queued.', 'lw-firewall' );
		}

		if ( $scan['sent'] ) {
			return __( 'Scan finished: no new or modified administrators. Earlier queued alerts were sent.', 'lw-firewall' );
		}

		return __( 'Scan finished: no new or modified administrators found.', 'lw-firewall' );
	}

	/**
	 * The scan response shape.
	 *
	 * @param string $state   disabled | clean | found.
	 * @param bool   $sent    Whether an alert mail went out.
	 * @param bool   $queued  Whether a mail was queued for retry.
	 * @param string $message Human-readable outcome.
	 * @return array{state: string, sent: bool, queued: bool, message: string}
	 */
	private static function shape( string $state, bool $sent, bool $queued, string $message ): array {
		return [
			'state'   => $state,
			'sent'    => $sent,
			'queued'  => $queued,
			'message' => $message,
		];
	}
}
