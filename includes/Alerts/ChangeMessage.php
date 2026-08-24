<?php
/**
 * Administrator identity-change alert message composition.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns identity changes on existing administrators into email text.
 *
 * The password field is never printed — only the fact that it changed. The
 * baseline stores a digest of the stored hash, so there is nothing to leak
 * even if the message were intercepted.
 */
final class ChangeMessage {

	/**
	 * Build the alert subject line.
	 *
	 * @param array<int, array{id: int, field: string, from: string, to: string}> $changes Detected changes.
	 * @return string
	 */
	public static function subject( array $changes ): string {
		$user_ids = array_values( array_unique( array_column( $changes, 'id' ) ) );

		if ( 1 === count( $user_ids ) ) {
			$user  = get_userdata( $user_ids[0] );
			$login = $user ? (string) $user->user_login : (string) $user_ids[0];

			return sprintf(
				/* translators: 1: site name, 2: username of the changed administrator. */
				__( '[%1$s] Security alert: administrator "%2$s" was modified', 'lw-firewall' ),
				MessageContext::site_name(),
				$login
			);
		}

		return sprintf(
			/* translators: 1: site name, 2: number of modified administrator accounts. */
			__( '[%1$s] Security alert: %2$d administrator accounts were modified', 'lw-firewall' ),
			MessageContext::site_name(),
			count( $user_ids )
		);
	}

	/**
	 * Build the plain-text alert body.
	 *
	 * @param array<int, array{id: int, field: string, from: string, to: string}> $changes Detected changes.
	 * @param string                                                              $source  Detection source key.
	 * @return string
	 */
	public static function body( array $changes, string $source ): string {
		$lines = array_merge(
			[
				__( 'The login details of an existing administrator account changed. This is how an account is taken over: rewriting the email address hands the attacker the password reset flow, and the user ID never changes, so the account still looks familiar.', 'lw-firewall' ),
				'',
			],
			MessageContext::header_lines( $source ),
			MessageContext::actor_lines( $source )
		);

		foreach ( self::group_by_user( $changes ) as $user_id => $user_changes ) {
			$lines[] = '';
			$lines[] = '----------------------------------------';

			foreach ( AdminDetector::describe( $user_id ) as $label => $value ) {
				$lines[] = $label . ': ' . $value;
			}

			$lines[] = '';
			$lines[] = __( 'What changed:', 'lw-firewall' );

			foreach ( $user_changes as $change ) {
				$lines[] = '  - ' . self::describe_change( $change );
			}
		}

		return implode(
			"\n",
			array_merge(
				$lines,
				MessageContext::footer_lines(
					__( 'If you did not make this change yourself, act now: reset the password, restore the correct email address, check the account for a second administrator it may have created, and review recently modified files and plugins.', 'lw-firewall' )
				)
			)
		);
	}

	/**
	 * Group a flat change list by user ID.
	 *
	 * @param array<int, array{id: int, field: string, from: string, to: string}> $changes Detected changes.
	 * @return array<int, array<int, array{id: int, field: string, from: string, to: string}>>
	 */
	private static function group_by_user( array $changes ): array {
		$grouped = [];

		foreach ( $changes as $change ) {
			$grouped[ (int) $change['id'] ][] = $change;
		}

		return $grouped;
	}

	/**
	 * One human-readable line describing a single field change.
	 *
	 * @param array{id: int, field: string, from: string, to: string} $change Change record.
	 * @return string
	 */
	private static function describe_change( array $change ): string {
		switch ( $change['field'] ) {
			case 'login':
				return sprintf(
					/* translators: 1: previous username, 2: new username. */
					__( 'Username changed from "%1$s" to "%2$s"', 'lw-firewall' ),
					$change['from'],
					$change['to']
				);

			case 'email':
				return sprintf(
					/* translators: 1: previous email address, 2: new email address. */
					__( 'Email address changed from "%1$s" to "%2$s"', 'lw-firewall' ),
					$change['from'],
					$change['to']
				);

			case 'pass':
				return __( 'Password changed (the new password is not shown)', 'lw-firewall' );

			default:
				/* translators: %s: name of the changed field. */
				return sprintf( __( '"%s" changed', 'lw-firewall' ), $change['field'] );
		}
	}
}
