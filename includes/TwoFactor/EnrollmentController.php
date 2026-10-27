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
 * - the factor binds only with the e-mail code as well (EnrollmentMail: the
 *   password alone must not be enough to take an account over);
 * - binding is claimed per account first (an atomic counter row,
 *   BIND_KEY), so two tokens confirming at once cannot both bind: the loser
 *   gets "start over";
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
	 * Results of confirm().
	 */
	public const CONFIRMED = 'confirmed';
	public const WRONG     = 'wrong';
	public const STALE     = 'stale';

	/**
	 * Usermeta key of the per-account binding claim (AttemptCounter row).
	 */
	public const BIND_KEY = '_lw_firewall_2fa_bind';

	/**
	 * Seconds a binding claim blocks a parallel one (it expires by itself).
	 */
	private const BIND_WINDOW = 60;

	/**
	 * Constructor.
	 *
	 * @param PendingLogin         $pending  Pending-login store.
	 * @param SecondFactorVerifier $verifier Code check (owns the clock).
	 * @param EnrollmentPage|null  $page     Screen; null = default.
	 * @param EnrollmentMail|null  $mail     E-mail code; null = default.
	 */
	public function __construct(
		private readonly PendingLogin $pending,
		private readonly SecondFactorVerifier $verifier,
		private readonly ?EnrollmentPage $page = null,
		private readonly ?EnrollmentMail $mail = null
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

		$record = $this->mail()->ensure_sent( $token, $user, $record );
		$this->page()->render_setup( $token, $user, $secret, $error, EnrollmentMail::required( $record ) ? EnrollmentMail::masked( $user ) : null );

		return true;
	}

	/**
	 * Check the e-mail and app codes; on success bind the factor and print the codes.
	 *
	 * The caller has claimed the attempt (per token and per account).
	 *
	 * @param string               $token  Pending token.
	 * @param WP_User              $user   Pending user.
	 * @param array<string, mixed> $record Record.
	 * @return string CONFIRMED, WRONG (count it) or STALE (start over, not a wrong answer).
	 */
	public function confirm( string $token, WP_User $user, array $record ): string {
		$secret = PendingLogin::enroll_secret( $record );
		if ( null === $secret ) {
			return self::STALE;
		}
		$mail_ok = $this->mail()->accepts( $token, $record, LoginRequest::mail_code() );
		$step    = $this->verifier->verify_enrollment( $secret, LoginRequest::code() );
		if ( ! $mail_ok || null === $step ) {
			return self::WRONG;
		}

		$id      = (int) $user->ID;
		$factors = new UserFactors( $id );
		if ( 1 !== $this->pending->counter()->increment( $id, self::BIND_KEY, self::BIND_WINDOW ) ) {
			return self::STALE;
		}
		// Checked inside the claim: a factor bound by any path before it wins.
		$bound = $factors->has_any() ? null : $this->bind( $token, $factors, $secret, $step, ! EnrollmentMail::required( $record ) );
		$this->pending->counter()->delete( $id, self::BIND_KEY );
		if ( null === $bound ) {
			return self::STALE;
		}

		/**
		 * Fires when a forced enrollment stored a new second factor at login.
		 *
		 * @param int    $user_id User ID.
		 * @param string $method  'totp'.
		 */
		do_action( 'lw_firewall_2fa_enrolled', $id, SecondFactorVerifier::TOTP );

		$this->page()->render_continue( $token, $bound );

		return self::CONFIRMED;
	}

	/**
	 * Store the factor and fresh recovery codes (inside the binding claim).
	 *
	 * The record turns `enrolled` first (single use of both codes, a fresh
	 * lifetime for the continue step); a vanished record binds nothing.
	 *
	 * @param string      $token   Pending token.
	 * @param UserFactors $factors Account store.
	 * @param string      $secret  Base32 secret.
	 * @param int         $step    Accepted time step.
	 * @param bool        $no_mail Whether the e-mail step was skipped (mail failure).
	 * @return string[]|null Plain recovery codes, or null when nothing was bound.
	 */
	private function bind( string $token, UserFactors $factors, string $secret, int $step, bool $no_mail ): ?array {
		$spent = array(
			'hash'    => '',
			'expires' => 0,
			'failed'  => $no_mail,
		);
		if ( ! $this->pending->patch(
			$token,
			array(
				'enrolled' => true,
				'mail'     => $spent,
			),
			PendingLogin::TTL
		) ) {
			return null;
		}

		$factors->save_totp( $secret );
		$factors->mark_totp_step( $step );
		$codes = RecoveryCodes::generate( self::RECOVERY_COUNT );
		$factors->set_recovery( $codes['hashes'] );

		return $codes['plain'];
	}

	/**
	 * E-mail code.
	 */
	private function mail(): EnrollmentMail {
		return $this->mail ?? new EnrollmentMail( $this->pending );
	}

	/**
	 * Screen.
	 */
	private function page(): EnrollmentPage {
		return $this->page ?? new EnrollmentPage();
	}
}
