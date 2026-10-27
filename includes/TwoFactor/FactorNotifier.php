<?php
/**
 * E-mails the account owner when a second factor is added or removed.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\IpSubject;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Listens to UserFactors::CHANGED_ACTION only, so every path (login
 * enrollment, profile, admin reset, CLI) notifies the same way. A hostile
 * enrollment with a stolen password, or a removed factor, is then noticed by
 * the real owner. The mail names what changed, when and from which address
 * (the IP subject: IPv6 by /64); it never carries a secret or a code.
 */
final class FactorNotifier {

	/**
	 * Register the listener.
	 */
	public function register(): void {
		add_action( UserFactors::CHANGED_ACTION, array( $this, 'notify' ), 10, 3 );
	}

	/**
	 * Send the notification (plain text).
	 *
	 * @param mixed $user_id User.
	 * @param mixed $change  'added' or 'removed'.
	 * @param mixed $factor  'totp', 'passkey' or 'all'.
	 */
	public function notify( $user_id, $change = '', $factor = '' ): void {
		$user = is_numeric( $user_id ) ? get_userdata( (int) $user_id ) : false;
		if ( ! $user instanceof WP_User || ! is_string( $user->user_email ?? null ) || '' === $user->user_email ) {
			return;
		}

		$site = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$ip   = IpDetector::get_ip();

		/* translators: %s: site name */
		$subject = sprintf( __( '[%s] Two-factor sign-in changed on your account', 'lw-firewall' ), $site );
		$lines   = array(
			/* translators: %s: user display name or login */
			sprintf( __( 'Hi %s,', 'lw-firewall' ), '' !== (string) $user->display_name ? $user->display_name : $user->user_login ),
			'',
			/* translators: 1: what changed, 2: site name */
			sprintf( __( '%1$s on your account at %2$s.', 'lw-firewall' ), self::describe( (string) $change, (string) $factor ), $site ),
			'',
			/* translators: %s: date and time in UTC */
			sprintf( __( 'Time: %s', 'lw-firewall' ), gmdate( 'Y-m-d H:i' ) . ' UTC' ),
			/* translators: %s: IP address or network */
			sprintf( __( 'From: %s', 'lw-firewall' ), '' !== $ip ? IpSubject::of( $ip ) : __( 'unknown', 'lw-firewall' ) ),
			'',
			__( 'If this was not you, contact an administrator of the site right away.', 'lw-firewall' ),
		);

		wp_mail( $user->user_email, $subject, implode( "\n", $lines ) );
	}

	/**
	 * Human description of the change.
	 *
	 * @param string $change 'added' or 'removed'.
	 * @param string $factor 'totp', 'passkey' or 'all'.
	 */
	private static function describe( string $change, string $factor ): string {
		if ( 'all' === $factor ) {
			return __( 'All two-factor sign-in methods were removed', 'lw-firewall' );
		}

		$added = 'added' === $change;
		if ( 'passkey' === $factor ) {
			return $added ? __( 'A passkey was added', 'lw-firewall' ) : __( 'A passkey was removed', 'lw-firewall' );
		}

		return $added ? __( 'An authenticator app was set up', 'lw-firewall' ) : __( 'The authenticator app was removed', 'lw-firewall' );
	}
}
