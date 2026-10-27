<?php
/**
 * The second-factor screen: shows the challenge and checks the answer.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use WP_Error;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Answers wp-login.php?action=lw_firewall_2fa for a pending login (see
 * LoginInterceptor for the whole flow). A right answer consumes the pending
 * record before the session cookie is set; a wrong one is counted by the
 * record (five per token, claimed atomically before the check), by the
 * module's own per-account FailureThrottle, and reported as `wp_login_failed`,
 * so the firewall's per-IP and per-username lockouts (when on) count it too.
 *
 * A forced-enrollment record (EnrollmentController) runs through the same
 * nonce and attempt claims; its code confirms a new factor instead, and the
 * session starts on the following "continue" POST.
 */
final class ChallengeController {

	/**
	 * Whether this request is completing a second factor (re-entry guard).
	 *
	 * @var bool
	 */
	private bool $completing = false;

	/**
	 * Constructor.
	 *
	 * @param PendingLogin              $pending  Pending-login store.
	 * @param SecondFactorVerifier      $verifier Factor checks.
	 * @param ChallengePage             $page     Screen.
	 * @param \Closure                  $halt     Ends the request.
	 * @param FailureThrottle           $throttle Per-account failure cap.
	 * @param RememberDevice|null       $remember   Trusted-device cookie; null = default.
	 * @param EnrollmentController|null $enrollment Forced enrollment; null = default.
	 */
	public function __construct(
		private readonly PendingLogin $pending,
		private readonly SecondFactorVerifier $verifier,
		private readonly ChallengePage $page,
		private readonly \Closure $halt,
		private readonly FailureThrottle $throttle,
		private readonly ?RememberDevice $remember = null,
		private readonly ?EnrollmentController $enrollment = null
	) {}

	/**
	 * Whether a second factor is being completed in this request.
	 */
	public function is_completing(): bool {
		return $this->completing;
	}

	/**
	 * Show the screen or check an answer (`login_form_lw_firewall_2fa`).
	 */
	public function handle(): void {
		nocache_headers();

		$token   = LoginRequest::token();
		$pending = '' === $token ? null : $this->pending->get( $token );
		$user    = null === $pending ? false : get_userdata( $pending['user_id'] );

		// An enrollment whose account got a factor meanwhile: sign in normally instead.
		if ( null === $pending || ! $user instanceof WP_User || EnrollmentController::enrolled_elsewhere( $pending, (int) $user->ID ) ) {
			$this->stop_expired( false );
			return;
		}

		if ( ! LoginRequest::is_post() ) {
			$this->show( $token, $user, '' );
			return;
		}

		if ( ! LoginRequest::nonce_ok( $token ) ) {
			$this->show( $token, $user, __( 'The form expired. Try again.', 'lw-firewall' ) );
			return;
		}

		if ( $pending['enrolled'] ) {
			$this->finish_enrollment( $token, $user );
			return;
		}

		$this->answer( $token, $user, $pending );
	}

	/**
	 * Claim the attempt, then check the answer (or the enrollment code).
	 *
	 * @param string               $token   Pending token.
	 * @param WP_User              $user    Pending user.
	 * @param array<string, mixed> $pending Pending record.
	 */
	private function answer( string $token, WP_User $user, array $pending ): void {
		if ( $this->throttle->is_blocked( (int) $user->ID ) ) {
			$this->page->render_throttled();
			( $this->halt )();
			return;
		}

		// Claimed atomically before the check: parallel requests share the five
		// answers of the token and the ten answers of the account.
		if ( ! $this->pending->begin_attempt( $token ) ) {
			$this->stop_expired( true );
			return;
		}
		if ( ! $this->throttle->claim( (int) $user->ID ) ) {
			$this->page->render_throttled();
			( $this->halt )();
			return;
		}

		if ( EnrollmentController::is_enrollment( $pending ) ) {
			if ( $this->enrollment()->confirm( $token, $user, $pending ) ) {
				$this->throttle->succeeded( (int) $user->ID );
				( $this->halt )();
				return;
			}
			$this->reject( $token, $user, SecondFactorVerifier::TOTP );
			return;
		}

		$method = LoginRequest::method();
		if ( $this->check( $method, (int) $user->ID, $pending ) ) {
			$this->complete( $token, $user, $method );
			return;
		}

		$this->reject( $token, $user, $method );
	}

	/**
	 * After a confirmed enrollment: only the "continue" button starts the session.
	 *
	 * @param string  $token Pending token.
	 * @param WP_User $user  Pending user.
	 */
	private function finish_enrollment( string $token, WP_User $user ): void {
		if ( ! LoginRequest::continues() ) {
			$this->show( $token, $user, '' );
			return;
		}

		$this->complete( $token, $user, SecondFactorVerifier::TOTP );
	}

	/**
	 * Render the challenge (issuing a fresh passkey challenge when offered).
	 *
	 * @param string  $token Pending token.
	 * @param WP_User $user  Pending user.
	 * @param string  $error Error message ('' = none).
	 */
	private function show( string $token, WP_User $user, string $error ): void {
		$record = $this->pending->get( $token );
		if ( null !== $record && EnrollmentController::is_enrollment( $record ) ) {
			if ( ! $this->enrollment()->show( $token, $user, $record, $error ) ) {
				$this->stop_expired( false );
				return;
			}
			( $this->halt )();
			return;
		}

		$id       = (int) $user->ID;
		$verifier = $this->verifier;
		$passkey  = $verifier->passkey_options( $user );
		if ( null !== $passkey ) {
			$this->pending->attach_passkey( $token, $passkey['key'] );
		}

		$totp     = $verifier->offers( $id, SecondFactorVerifier::TOTP );
		$recovery = $verifier->offers( $id, SecondFactorVerifier::RECOVERY );

		$this->page->render(
			$token,
			$user,
			$error,
			array(
				'mode'     => self::mode( LoginRequest::mode(), $totp, $recovery, null !== $passkey ),
				'totp'     => $totp,
				'recovery' => $recovery,
				'passkey'  => $passkey['options'] ?? null,
			)
		);
		( $this->halt )();
	}

	/**
	 * Which screen mode to show.
	 *
	 * @param string $requested Requested mode.
	 * @param bool   $totp      TOTP offered.
	 * @param bool   $recovery  Recovery codes offered.
	 * @param bool   $passkey   Passkey offered.
	 */
	private static function mode( string $requested, bool $totp, bool $recovery, bool $passkey ): string {
		if ( ChallengePage::MODE_RECOVERY === $requested && $recovery ) {
			return ChallengePage::MODE_RECOVERY;
		}
		if ( $totp ) {
			return ChallengePage::MODE_TOTP;
		}
		if ( $passkey ) {
			return ChallengePage::MODE_PASSKEY;
		}

		return $recovery ? ChallengePage::MODE_RECOVERY : ChallengePage::MODE_NONE;
	}

	/**
	 * Check the submitted answer.
	 *
	 * @param string               $method  Submitted method.
	 * @param int                  $user_id Pending user.
	 * @param array<string, mixed> $pending Pending record (holds the passkey challenge key).
	 */
	private function check( string $method, int $user_id, array $pending ): bool {
		$verifier = $this->verifier;

		return match ( $method ) {
			SecondFactorVerifier::TOTP     => $verifier->verify_totp( $user_id, LoginRequest::code() ),
			SecondFactorVerifier::RECOVERY => $verifier->verify_recovery( $user_id, LoginRequest::code() ),
			SecondFactorVerifier::PASSKEY  => $verifier->verify_passkey( $user_id, (string) $pending['passkey_key'], LoginRequest::passkey() ),
			default                        => false,
		};
	}

	/**
	 * Second factor passed: consume the token, then start the session.
	 *
	 * @param string  $token  Pending token.
	 * @param WP_User $user   User.
	 * @param string  $method Method used.
	 */
	private function complete( string $token, WP_User $user, string $method ): void {
		$record = $this->pending->consume( $token );
		if ( null === $record ) {
			$this->stop_expired( false );
			return;
		}

		$this->throttle->succeeded( (int) $user->ID );
		$this->completing = true;
		wp_set_auth_cookie( (int) $user->ID, $record['remember'], $record['secure'] );
		wp_set_current_user( (int) $user->ID );
		$days = RememberDevice::days();
		if ( $days > 0 && LoginRequest::remember_device() ) {
			( $this->remember ?? new RememberDevice() )->issue( (int) $user->ID, $days );
		}

		/**
		 * Fires when a login passed its second factor and the session is set.
		 *
		 * @param int    $user_id User ID.
		 * @param string $method  'totp', 'recovery' or 'passkey'.
		 */
		do_action( 'lw_firewall_2fa_passed', (int) $user->ID, $method );

		$this->redirect( LoginRequest::destination( $record['redirect_to'], $user ) );
	}

	/**
	 * Wrong answer: count it everywhere a failed login counts.
	 *
	 * @param string  $token  Pending token.
	 * @param WP_User $user   User.
	 * @param string  $method Method tried.
	 */
	private function reject( string $token, WP_User $user, string $method ): void {
		$left = $this->pending->fail( $token );
		$this->throttle->record_failure( (int) $user->ID );

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook: the brute-force counters (per IP and per username) count this attempt.
		do_action( 'wp_login_failed', $user->user_login, new WP_Error( 'lwfw_2fa_invalid', __( 'Wrong second-factor answer.', 'lw-firewall' ) ) );
		FailureLog::record( FailureLog::reason_for( $method ) );

		if ( 0 === $left ) {
			$this->stop_expired( true );
			return;
		}

		$message = SecondFactorVerifier::PASSKEY === $method
			? __( 'The passkey was not accepted. Try again or use another method.', 'lw-firewall' )
			: __( 'That code is not valid. Try again.', 'lw-firewall' );
		$this->show( $token, $user, $message );
	}

	/**
	 * Show the "start over" screen and halt.
	 *
	 * @param bool $locked Whether the answers are used up.
	 */
	private function stop_expired( bool $locked ): void {
		$this->page->render_expired( $locked );
		( $this->halt )();
	}

	/**
	 * Forced-enrollment handler.
	 */
	private function enrollment(): EnrollmentController {
		return $this->enrollment ?? new EnrollmentController( $this->pending, $this->verifier );
	}

	/**
	 * Redirect and halt.
	 *
	 * @param string $url Target.
	 */
	private function redirect( string $url ): void {
		wp_safe_redirect( $url );
		( $this->halt )();
	}
}
