<?php
/**
 * Re-authentication of a sensitive profile action.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Rest;

use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\LoginRequest;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\SecondFactorVerifier;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;
use WP_Error;
use WP_REST_Request;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A logged-in cookie alone must not be enough to add, remove or change a
 * second factor.
 *
 * - check(): the profile's own actions. Once the account has any factor,
 *   only a FACTOR proves it: a fresh TOTP code (`code`, replay-guarded like
 *   at login), an unused recovery code (`recovery_code`, consumed) or a
 *   passkey assertion (`passkey_key` from POST /2fa/reauth/passkey/options +
 *   `passkey`) of this very user. The password is not accepted then: core
 *   lets a signed-in user set a new password without the old one, so a
 *   stolen session could otherwise pass with a password it chose itself.
 *   An account without any factor confirms with `current_password` (a stolen
 *   session gains nothing beyond what it already has there).
 * - check_password(): the admin's own password (resetting another user).
 *
 * Every attempt claims a slot of the account's FailureThrottle before it is
 * checked (the same budget as the login step), so a stolen session cannot
 * guess its way through.
 */
final class ReAuth {

	public const REQUIRED_CODE = 'lwfw_2fa_reauth_required';
	public const FAILED_CODE   = 'lwfw_2fa_reauth_failed';
	public const BLOCKED_CODE  = 'lwfw_2fa_reauth_blocked';

	/**
	 * Longest accepted password (bcrypt reads 72 bytes; this caps hashing work).
	 */
	private const PASSWORD_MAX = 4096;

	/**
	 * Cap on the passkey assertion's total field length.
	 */
	private const PASSKEY_MAX = 65536;

	/**
	 * Constructor.
	 *
	 * @param FailureThrottle|null $throttle Per-account answer budget.
	 * @param \Closure|null        $clock    Returns the current Unix time (tests); null = time().
	 * @param PasskeyService|null  $passkeys Passkey ceremonies; null = default.
	 */
	public function __construct(
		private readonly ?FailureThrottle $throttle = null,
		private readonly ?\Closure $clock = null,
		private readonly ?PasskeyService $passkeys = null
	) {}

	/**
	 * Check the proof of a self-service action of this user.
	 *
	 * @param WP_User         $user    Signed-in account.
	 * @param WP_REST_Request $request Request.
	 * @return bool|WP_Error True, or the refusal.
	 */
	public function check( WP_User $user, WP_REST_Request $request ): bool|WP_Error {
		if ( ! ( new UserFactors( (int) $user->ID ) )->has_any() ) {
			return $this->check_password( $user, $request );
		}

		$proof = self::factor_proof( $request );
		if ( null === $proof ) {
			return new WP_Error( self::REQUIRED_CODE, __( 'Confirm it with a code from your authenticator app, a recovery code or your passkey.', 'lw-firewall' ), array( 'status' => 403 ) );
		}

		return $this->claimed( $user, fn (): bool => $this->accepts_factor( (int) $user->ID, $proof ) );
	}

	/**
	 * Check the account's current password (admin reset, accounts without a factor).
	 *
	 * @param WP_User         $user    Account whose password is asked.
	 * @param WP_REST_Request $request Request.
	 * @return bool|WP_Error True, or the refusal.
	 */
	public function check_password( WP_User $user, WP_REST_Request $request ): bool|WP_Error {
		$password = self::param( $request, 'current_password' );
		if ( '' === $password ) {
			return new WP_Error( self::REQUIRED_CODE, __( 'Confirm it with your password.', 'lw-firewall' ), array( 'status' => 403 ) );
		}

		return $this->claimed(
			$user,
			static fn (): bool => strlen( $password ) <= self::PASSWORD_MAX && wp_check_password( $password, (string) $user->user_pass, (int) $user->ID )
		);
	}

	/**
	 * Claim an attempt of the account's budget, then run the check.
	 *
	 * @param WP_User  $user  Account.
	 * @param \Closure $check Returns whether the proof is right.
	 * @return bool|WP_Error
	 */
	private function claimed( WP_User $user, \Closure $check ): bool|WP_Error {
		$id       = (int) $user->ID;
		$throttle = $this->throttle ?? new FailureThrottle();
		if ( $throttle->is_blocked( $id ) || ! $throttle->claim( $id ) ) {
			return new WP_Error( self::BLOCKED_CODE, __( 'Too many wrong attempts. Wait 15 minutes and try again.', 'lw-firewall' ), array( 'status' => 429 ) );
		}

		if ( $check() ) {
			$throttle->succeeded( $id );
			return true;
		}

		$throttle->record_failure( $id );

		return new WP_Error( self::FAILED_CODE, __( 'The confirmation was not accepted. Try again.', 'lw-firewall' ), array( 'status' => 403 ) );
	}

	/**
	 * Which factor the request offers (the first non-empty one).
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{0: string, 1: mixed}|null [ method, answer ], or null when none.
	 */
	private static function factor_proof( WP_REST_Request $request ): ?array {
		$code = self::param( $request, 'code' );
		if ( '' !== $code ) {
			return array( SecondFactorVerifier::TOTP, $code );
		}
		$recovery = self::param( $request, 'recovery_code' );
		if ( '' !== $recovery ) {
			return array( SecondFactorVerifier::RECOVERY, $recovery );
		}
		$key = self::param( $request, 'passkey_key' );
		if ( '' !== $key ) {
			return array( SecondFactorVerifier::PASSKEY, array( $key, self::assertion( $request->get_param( 'passkey' ) ) ) );
		}

		return null;
	}

	/**
	 * Whether the offered factor is right (each marks what it used).
	 *
	 * @param int                        $user_id Account.
	 * @param array{0: string, 1: mixed} $proof   Method and answer.
	 */
	private function accepts_factor( int $user_id, array $proof ): bool {
		[ $method, $answer ] = $proof;
		$verifier            = new SecondFactorVerifier( $this->passkeys, $this->clock );

		if ( SecondFactorVerifier::PASSKEY === $method ) {
			// The challenge must be a 2FA challenge bound to exactly this user.
			return is_array( $answer ) && $verifier->verify_passkey( $user_id, (string) $answer[0], (array) $answer[1] );
		}
		if ( ! is_string( $answer ) ) {
			return false;
		}

		return SecondFactorVerifier::TOTP === $method
			? $verifier->verify_totp( $user_id, $answer )
			: $verifier->verify_recovery( $user_id, $answer );
	}

	/**
	 * The assertion's base64url string fields (size-capped).
	 *
	 * @param mixed $raw Request value.
	 * @return array<string, string>
	 */
	private static function assertion( $raw ): array {
		$fields = LoginRequest::passkey_fields( $raw );

		return array_sum( array_map( 'strlen', $fields ) ) > self::PASSKEY_MAX ? array() : $fields;
	}

	/**
	 * A string parameter, unmodified ('' when absent).
	 *
	 * @param WP_REST_Request $request Request.
	 * @param string          $name    Parameter.
	 */
	private static function param( WP_REST_Request $request, string $name ): string {
		$value = $request->get_param( $name );

		return is_string( $value ) ? $value : '';
	}
}
