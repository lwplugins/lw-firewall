<?php
/**
 * The second-factor screen: shows the challenge and checks the answer.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\Logger;
use WP_Error;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Answers wp-login.php?action=lw_firewall_2fa for a pending login (see
 * LoginInterceptor for the whole flow). A right answer consumes the pending
 * record before the session cookie is set; a wrong one is counted by the
 * record (five per token) and reported as `wp_login_failed`, so the per-IP
 * and per-username lockouts count it like a wrong password.
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
	 * @param PendingLogin         $pending  Pending-login store.
	 * @param SecondFactorVerifier $verifier Factor checks.
	 * @param ChallengePage        $page     Screen.
	 * @param \Closure             $halt     Ends the request.
	 */
	public function __construct(
		private readonly PendingLogin $pending,
		private readonly SecondFactorVerifier $verifier,
		private readonly ChallengePage $page,
		private readonly \Closure $halt
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

		if ( null === $pending || ! $user instanceof WP_User ) {
			$this->page->render_expired( false );
			( $this->halt )();
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

		$method = LoginRequest::method();
		if ( $this->check( $method, (int) $user->ID, $pending ) ) {
			$this->complete( $token, $user, $method );
			return;
		}

		$this->reject( $token, $user, $method );
	}

	/**
	 * Render the challenge (issuing a fresh passkey challenge when offered).
	 *
	 * @param string  $token Pending token.
	 * @param WP_User $user  Pending user.
	 * @param string  $error Error message ('' = none).
	 */
	private function show( string $token, WP_User $user, string $error ): void {
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

		return $passkey ? ChallengePage::MODE_PASSKEY : ChallengePage::MODE_RECOVERY;
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
			$this->page->render_expired( false );
			( $this->halt )();
			return;
		}

		$this->completing = true;
		wp_set_auth_cookie( (int) $user->ID, $record['remember'] );
		wp_set_current_user( (int) $user->ID );

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

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook: the brute-force counters (per IP and per username) count this attempt.
		do_action( 'wp_login_failed', $user->user_login, new WP_Error( 'lwfw_2fa_invalid', __( 'Wrong second-factor answer.', 'lw-firewall' ) ) );
		Logger::log(
			array(
				'ip'     => IpDetector::get_ip(),
				'reason' => self::failure_reason( $method ),
				'ua'     => LoginRequest::user_agent(),
				'url'    => LoginRequest::uri(),
			)
		);

		if ( 0 === $left ) {
			$this->page->render_expired( true );
			( $this->halt )();
			return;
		}

		$message = SecondFactorVerifier::PASSKEY === $method
			? __( 'The passkey was not accepted. Try again or use another method.', 'lw-firewall' )
			: __( 'That code is not valid. Try again.', 'lw-firewall' );
		$this->show( $token, $user, $message );
	}

	/**
	 * Log reason of a wrong answer.
	 *
	 * @param string $method Method tried.
	 */
	public static function failure_reason( string $method ): string {
		return SecondFactorVerifier::PASSKEY === $method ? 'twofa_passkey_failed' : 'twofa_failed';
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
