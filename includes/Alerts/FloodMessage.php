<?php
/**
 * Password-reset flood alert message composition.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns a tripped password-reset limit into email text.
 *
 * One message per limit per hour, so this describes a situation rather than a
 * single request: the interesting fact is "the site is being flooded", not
 * "request #47 was refused".
 */
final class FloodMessage {

	/**
	 * Build the alert subject line.
	 *
	 * @return string
	 */
	public static function subject(): string {
		return sprintf(
			/* translators: %s: site name. */
			__( '[%s] Password reset flood blocked', 'lw-firewall' ),
			MessageContext::site_name()
		);
	}

	/**
	 * Build the plain-text alert body.
	 *
	 * @param string $verdict Which limit was hit.
	 * @param string $ip      Requesting IP.
	 * @param int    $user_id Target account, or 0 when unknown.
	 * @return string
	 */
	public static function body( string $verdict, string $ip, int $user_id ): string {
		$lines = array_merge(
			[
				__( 'LW Firewall started refusing password reset requests on your site.', 'lw-firewall' ),
				'',
				self::explain( $verdict ),
				'',
			],
			MessageContext::header_lines( 'reset_flood' )
		);

		if ( '' !== $ip ) {
			/* translators: %s: IP address. */
			$lines[] = sprintf( __( 'Requesting IP: %s', 'lw-firewall' ), $ip );
		}

		foreach ( self::target_lines( $user_id ) as $line ) {
			$lines[] = $line;
		}

		$lines[] = '';
		$lines[] = __( 'Further blocks in the next hour will not be emailed, so this alert cannot become the flood it reports. Blocked requests are still written to the firewall log when logging is enabled.', 'lw-firewall' );

		return implode(
			"\n",
			array_merge(
				$lines,
				MessageContext::footer_lines(
					__( 'No action is needed if this looks like ordinary bot noise — the requests were refused and no reset emails were sent. Investigate if a specific account is being targeted repeatedly: whoever is asking wants that person\'s inbox flooded, usually to bury a real notification or to set up a phishing email that looks like the reset.', 'lw-firewall' )
				)
			)
		);
	}

	/**
	 * One sentence explaining which limit was reached.
	 *
	 * @param string $verdict Which limit was hit.
	 * @return string
	 */
	private static function explain( string $verdict ): string {
		switch ( $verdict ) {
			case 'ip':
				return __( 'A single IP address asked for more password resets than the per-IP limit allows.', 'lw-firewall' );

			case 'user':
				return __( 'One account received more reset requests than its limit allows — the requests may be coming from many different IP addresses, which is what an inbox-flooding attack looks like.', 'lw-firewall' );

			case 'global':
				return __( 'The site reached its hourly cap on reset emails. This cap exists to protect your hosting mail quota and stop your domain being flagged as a spam source.', 'lw-firewall' );

			case 'spam':
				return __( 'A request was submitted without a valid proof-of-render token, meaning it did not come from the lost-password form — that is a direct bot POST.', 'lw-firewall' );

			default:
				return __( 'A password reset request was refused.', 'lw-firewall' );
		}
	}

	/**
	 * Lines naming the targeted account, when there is one.
	 *
	 * @param int $user_id Target account, or 0 when unknown.
	 * @return array<int, string>
	 */
	private static function target_lines( int $user_id ): array {
		if ( $user_id <= 0 ) {
			return [];
		}

		$user = get_userdata( $user_id );

		if ( ! $user instanceof WP_User ) {
			return [];
		}

		$lines = [
			sprintf(
				/* translators: 1: username, 2: user ID. */
				__( 'Targeted account: %1$s (ID %2$d)', 'lw-firewall' ),
				(string) $user->user_login,
				$user_id
			),
		];

		if ( in_array( 'administrator', (array) $user->roles, true ) ) {
			$lines[] = __( 'This account is an administrator. Treat repeated reset attempts against it as a targeted attack, not background noise.', 'lw-firewall' );
		}

		return $lines;
	}
}
