<?php
/**
 * Forced TOTP enrollment on the second-factor screen.
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
 * Used by ChallengeController for a pending login that must set up a second
 * factor (Enforcement::must_enroll_now()). The controller keeps the request
 * flow (nonce, per-token and per-account attempt claims, failure counting,
 * the final session); this class owns what differs:
 *
 * - the secret was generated at the password step and lives sealed in the
 *   pending record, never in the page's form fields;
 * - a right code stores the TOTP factor (its step as the replay guard),
 *   replaces the recovery codes and prints them once: the plain codes are
 *   never stored, a later visit of the same token shows the "continue"
 *   step without them;
 * - the session starts only on the separate "continue" POST.
 *
 * Passkey enrollment is not offered on the login screen (profile only).
 */
final class EnrollmentController {

	/**
	 * Recovery codes issued with the enrollment.
	 */
	public const RECOVERY_COUNT = 10;

	/**
	 * Constructor.
	 *
	 * @param PendingLogin         $pending  Pending-login store.
	 * @param SecondFactorVerifier $verifier Code check (owns the clock).
	 * @param EnrollmentPage|null  $page     Screen; null = default.
	 */
	public function __construct(
		private readonly PendingLogin $pending,
		private readonly SecondFactorVerifier $verifier,
		private readonly ?EnrollmentPage $page = null
	) {}

	/**
	 * Whether a pending record is a forced enrollment.
	 *
	 * @param array<string, mixed> $record Record from PendingLogin::get().
	 */
	public static function is_enrollment( array $record ): bool {
		return is_string( $record['enroll'] ?? null ) && '' !== $record['enroll'];
	}

	/**
	 * Whether the account got a factor some other way while this record waited.
	 *
	 * @param array<string, mixed> $record  Record.
	 * @param int                  $user_id User.
	 */
	public static function enrolled_elsewhere( array $record, int $user_id ): bool {
		return self::is_enrollment( $record ) && empty( $record['enrolled'] ) && ( new UserFactors( $user_id ) )->has_any();
	}

	/**
	 * Render the setup screen, or the "continue" step once confirmed.
	 *
	 * @param string               $token  Pending token.
	 * @param WP_User              $user   Pending user.
	 * @param array<string, mixed> $record Record.
	 * @param string               $error  Error message ('' = none).
	 * @return bool False when the secret can no longer be read (start over).
	 */
	public function show( string $token, WP_User $user, array $record, string $error ): bool {
		if ( ! empty( $record['enrolled'] ) ) {
			$this->page()->render_continue( $token, array() );
			return true;
		}

		$secret = PendingLogin::enroll_secret( $record );
		if ( null === $secret ) {
			return false;
		}

		$this->page()->render_setup( $token, $user, $secret, $error );

		return true;
	}

	/**
	 * Check the confirming code; on success store the factor and print the codes.
	 *
	 * The caller has claimed the attempt (per token and per account).
	 *
	 * @param string               $token  Pending token.
	 * @param WP_User              $user   Pending user.
	 * @param array<string, mixed> $record Record.
	 * @return bool Whether the code was right and the factor is stored.
	 */
	public function confirm( string $token, WP_User $user, array $record ): bool {
		$secret = PendingLogin::enroll_secret( $record );
		$step   = null === $secret ? null : $this->verifier->verify_enrollment( $secret, LoginRequest::code() );
		if ( null === $secret || null === $step ) {
			return false;
		}

		$id      = (int) $user->ID;
		$factors = new UserFactors( $id );
		if ( $factors->has_any() || ! $this->pending->mark_enrolled( $token ) ) {
			return false;
		}

		$factors->save_totp( $secret );
		$factors->mark_totp_step( $step );
		$codes = RecoveryCodes::generate( self::RECOVERY_COUNT );
		$factors->set_recovery( $codes['hashes'] );

		/**
		 * Fires when a forced enrollment stored a new second factor at login.
		 *
		 * @param int    $user_id User ID.
		 * @param string $method  'totp'.
		 */
		do_action( 'lw_firewall_2fa_enrolled', $id, SecondFactorVerifier::TOTP );

		$this->page()->render_continue( $token, $codes['plain'] );

		return true;
	}

	/**
	 * Screen.
	 */
	private function page(): EnrollmentPage {
		return $this->page ?? new EnrollmentPage();
	}
}
