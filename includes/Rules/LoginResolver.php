<?php
/**
 * Resolves a typed login to the account WordPress would log into.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WordPress finds the user through sanitize_user() and a case- and
 * accent-insensitive collation, so "Admin", a zero-width-space variant or a
 * full-width first letter all log into "admin". Failures must be counted
 * under that canonical login, or every variant gets a fresh counter. Only a
 * login that matches no account falls back to the typed string.
 */
final class LoginResolver {

	/**
	 * The canonical login for a typed login or email.
	 *
	 * @param string $login Typed login or email address.
	 * @return string The account's user_login, the trimmed input for an unknown account, or ''.
	 */
	public static function resolve( string $login ): string {
		$login = trim( $login );

		if ( '' === $login ) {
			return '';
		}

		$user = get_user_by( 'login', $login );

		if ( ! $user && is_email( $login ) ) {
			$user = get_user_by( 'email', $login );
		}

		return $user ? (string) $user->user_login : $login;
	}
}
