<?php
/**
 * New-administrator alert message composition.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns a set of newly detected administrator IDs into subject and body text.
 *
 * Kept apart from AlertMailer so wording changes never touch delivery logic
 * and vice versa.
 */
final class AlertMessage {

	/**
	 * Build the alert subject line.
	 *
	 * @param array<int, int> $user_ids New administrator user IDs.
	 * @return string
	 */
	public static function subject( array $user_ids ): string {
		if ( 1 === count( $user_ids ) ) {
			$user  = get_userdata( $user_ids[0] );
			$login = $user ? (string) $user->user_login : (string) $user_ids[0];

			return sprintf(
				/* translators: 1: site name, 2: username of the new administrator. */
				__( '[%1$s] Security alert: new administrator "%2$s"', 'lw-firewall' ),
				MessageContext::site_name(),
				$login
			);
		}

		return sprintf(
			/* translators: 1: site name, 2: number of new administrator accounts. */
			__( '[%1$s] Security alert: %2$d new administrator accounts', 'lw-firewall' ),
			MessageContext::site_name(),
			count( $user_ids )
		);
	}

	/**
	 * Build the plain-text alert body.
	 *
	 * @param array<int, int> $user_ids New administrator user IDs.
	 * @param string          $source   Detection source key.
	 * @return string
	 */
	public static function body( array $user_ids, string $source ): string {
		$lines = array_merge(
			[
				__( 'An account with administrator privileges appeared on your site.', 'lw-firewall' ),
				'',
			],
			MessageContext::header_lines( $source ),
			MessageContext::actor_lines( $source )
		);

		foreach ( $user_ids as $user_id ) {
			$lines[] = '';
			$lines[] = '----------------------------------------';

			foreach ( AdminDetector::describe( (int) $user_id ) as $label => $value ) {
				$lines[] = $label . ': ' . $value;
			}
		}

		return implode(
			"\n",
			array_merge(
				$lines,
				MessageContext::footer_lines(
					__( 'If you did not expect this, treat the site as compromised: remove the account, rotate all administrator passwords, and review recently modified files and plugins.', 'lw-firewall' )
				)
			)
		);
	}

	/**
	 * Build the delivery-test subject line.
	 *
	 * @return string
	 */
	public static function test_subject(): string {
		return sprintf(
			/* translators: %s: site name. */
			__( '[%s] LW Firewall test alert', 'lw-firewall' ),
			MessageContext::site_name()
		);
	}

	/**
	 * Build the delivery-test body.
	 *
	 * @return string
	 */
	public static function test_body(): string {
		return implode(
			"\n",
			[
				__( 'This is a test message from LW Firewall.', 'lw-firewall' ),
				'',
				__( 'If you received it, administrator alerts will reach this address.', 'lw-firewall' ),
				'',
				/* translators: %s: site URL. */
				sprintf( __( 'Site: %s', 'lw-firewall' ), home_url( '/' ) ),
				/* translators: %s: local date and time. */
				sprintf( __( 'Time: %s', 'lw-firewall' ), current_time( 'mysql' ) ),
			]
		);
	}
}
