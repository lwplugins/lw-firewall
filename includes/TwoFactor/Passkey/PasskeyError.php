<?php
/**
 * Stable passkey error codes and their user-facing messages.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Passkey;

use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Library exception text never reaches a user: it is only logged (WP_DEBUG_LOG).
 */
final class PasskeyError {

	public const INVALID   = 'lwfw_passkey_invalid';
	public const UNKNOWN   = 'lwfw_passkey_unknown';
	public const HANDLE    = 'lwfw_passkey_handle';
	public const CLONED    = 'lwfw_passkey_clone';
	public const CHALLENGE = 'lwfw_passkey_challenge';
	public const LIMIT     = 'lwfw_passkey_limit';

	/**
	 * Build the error.
	 *
	 * @param string          $code  One of the constants.
	 * @param \Throwable|null $cause Library exception (logged only).
	 */
	public static function make( string $code, ?\Throwable $cause = null ): WP_Error {
		if ( null !== $cause && defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debug-log only diagnostics; never shown to users.
			error_log( sprintf( 'LW Firewall passkey %s: %s', $code, $cause->getMessage() ) );
		}

		return new WP_Error( $code, self::message( $code ), array( 'status' => 400 ) );
	}

	/**
	 * Translated message for a code.
	 *
	 * @param string $code Error code.
	 */
	private static function message( string $code ): string {
		switch ( $code ) {
			case self::UNKNOWN:
				return __( 'This passkey is not registered for this account.', 'lw-firewall' );
			case self::HANDLE:
				return __( 'This passkey belongs to a different account.', 'lw-firewall' );
			case self::CLONED:
				return __( 'This passkey was rejected because it may have been copied. Remove it and register it again.', 'lw-firewall' );
			case self::CHALLENGE:
				return __( 'The passkey request has expired. Please try again.', 'lw-firewall' );
			case self::LIMIT:
				return __( 'This passkey cannot be added: it is already registered, or the limit of 10 passkeys is reached.', 'lw-firewall' );
			default:
				return __( 'The passkey could not be verified. Please try again.', 'lw-firewall' );
		}
	}
}
