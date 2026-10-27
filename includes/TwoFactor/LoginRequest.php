<?php
/**
 * Reads the login and challenge request fields.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Every superglobal the second-factor flow reads goes through here, sanitized
 * and typed. The login form fields (rememberme, redirect_to / WooCommerce's
 * redirect) are read while core processes its own login POST, which has no
 * nonce; the challenge form fields are only used after nonce_ok().
 *
 * phpcs:disable WordPress.Security.NonceVerification -- See the class comment: login form (core, no nonce) or after nonce_ok().
 */
final class LoginRequest {

	/**
	 * Upper bound of a posted passkey assertion (bytes of JSON).
	 */
	private const PASSKEY_MAX = 16384;

	/**
	 * "Remember me" of the login form (wp-login.php and WooCommerce both post `rememberme`).
	 */
	public static function remember(): bool {
		return ! empty( $_POST['rememberme'] );
	}

	/**
	 * The "Remember this device" checkbox of the challenge screen.
	 */
	public static function remember_device(): bool {
		return ! empty( $_POST['lwfw_remember_device'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read after the challenge nonce check.
	}

	/**
	 * The requested redirect of the login form, validated ('' = none).
	 *
	 * The wp-login.php form posts `redirect_to`, WooCommerce posts `redirect`.
	 */
	public static function redirect_to(): string {
		$raw = '';
		if ( isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ) {
			$raw = sanitize_url( wp_unslash( $_REQUEST['redirect_to'] ) );
		}
		if ( '' === trim( $raw ) && isset( $_REQUEST['redirect'] ) && is_string( $_REQUEST['redirect'] ) ) {
			$raw = sanitize_url( wp_unslash( $_REQUEST['redirect'] ) );
		}

		return '' === trim( $raw ) ? '' : (string) wp_validate_redirect( $raw, admin_url() );
	}

	/**
	 * Where a completed login goes: what core wp-login.php would pick.
	 *
	 * @param string  $stored Validated redirect from the pending record ('' = default).
	 * @param WP_User $user   User.
	 */
	public static function destination( string $stored, WP_User $user ): string {
		$target = '' !== $stored ? $stored : admin_url();

		/** This filter is documented in wp-login.php */
		$target = (string) apply_filters( 'login_redirect', $target, $stored, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.

		// Back to the login screen would only show the form again: go to the dashboard.
		$path = wp_parse_url( $target, PHP_URL_PATH );
		if ( is_string( $path ) && str_ends_with( $path, '/wp-login.php' ) ) {
			$target = admin_url();
		}

		if ( '' === $target || admin_url() === $target ) {
			if ( ! user_can( $user, 'edit_posts' ) ) {
				$target = user_can( $user, 'read' ) ? admin_url( 'profile.php' ) : home_url();
			}
		}

		return (string) wp_validate_redirect( $target, admin_url() );
	}

	/**
	 * Pending token from the URL or the form.
	 */
	public static function token(): string {
		$raw = isset( $_REQUEST['token'] ) && is_string( $_REQUEST['token'] ) ? sanitize_key( wp_unslash( $_REQUEST['token'] ) ) : '';

		return 1 === preg_match( '/^[0-9a-f]{32}$/D', $raw ) ? $raw : '';
	}

	/**
	 * Whether the challenge form was submitted.
	 */
	public static function is_post(): bool {
		return 'POST' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '' );
	}

	/**
	 * Whether the challenge form carries a valid nonce for this token.
	 *
	 * @param string $token Pending token.
	 */
	public static function nonce_ok( string $token ): bool {
		$nonce = isset( $_POST['lwfw_2fa_nonce'] ) && is_string( $_POST['lwfw_2fa_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['lwfw_2fa_nonce'] ) ) : '';

		return '' !== $nonce && false !== wp_verify_nonce( $nonce, 'lw_firewall_2fa_' . $token );
	}

	/**
	 * Submitted method: totp, recovery or passkey ('' = unknown).
	 */
	public static function method(): string {
		$raw = isset( $_POST['lwfw_method'] ) && is_string( $_POST['lwfw_method'] ) ? sanitize_key( wp_unslash( $_POST['lwfw_method'] ) ) : '';

		return in_array( $raw, array( SecondFactorVerifier::TOTP, SecondFactorVerifier::RECOVERY, SecondFactorVerifier::PASSKEY ), true ) ? $raw : '';
	}

	/**
	 * Submitted TOTP or recovery code.
	 */
	public static function code(): string {
		$raw = isset( $_POST['lwfw_code'] ) && is_string( $_POST['lwfw_code'] ) ? sanitize_text_field( wp_unslash( $_POST['lwfw_code'] ) ) : '';

		return substr( $raw, 0, 64 );
	}

	/**
	 * Submitted passkey assertion (base64url string fields only).
	 *
	 * @return array<string, string>
	 */
	public static function passkey(): array {
		// JSON of base64url strings: sanitize_text_field() leaves it intact; each field is re-validated below and by AssertionInput.
		$raw = isset( $_POST['lwfw_passkey'] ) && is_string( $_POST['lwfw_passkey'] ) ? sanitize_text_field( wp_unslash( $_POST['lwfw_passkey'] ) ) : '';
		if ( '' === $raw || strlen( $raw ) > self::PASSKEY_MAX ) {
			return array();
		}

		$data = json_decode( $raw, true );
		if ( ! is_array( $data ) ) {
			return array();
		}

		$out = array();
		foreach ( array( 'id', 'clientDataJSON', 'authenticatorData', 'signature', 'userHandle' ) as $field ) {
			if ( isset( $data[ $field ] ) && is_string( $data[ $field ] ) && 1 === preg_match( '/^[A-Za-z0-9_-]*$/D', $data[ $field ] ) ) {
				$out[ $field ] = $data[ $field ];
			}
		}

		return $out;
	}

	/**
	 * Requested screen mode ('' or 'recovery').
	 */
	public static function mode(): string {
		$raw = isset( $_GET['mode'] ) && is_string( $_GET['mode'] ) ? sanitize_key( wp_unslash( $_GET['mode'] ) ) : '';

		return ChallengePage::MODE_RECOVERY === $raw ? ChallengePage::MODE_RECOVERY : '';
	}

	/**
	 * User agent for the log (sanitized, 200 chars).
	 */
	public static function user_agent(): string {
		return substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 );
	}

	/**
	 * Request URI for the log, without the query string (it carries the token).
	 */
	public static function uri(): string {
		$uri = sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) );

		return (string) strtok( $uri, '?' );
	}
}
