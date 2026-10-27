<?php
/**
 * Holds a password-only login until the second factor is answered.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use WP_User;
use WP_Session_Tokens;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Flow: core wp_signon() checks the password, calls wp_set_auth_cookie(),
 * then fires `wp_login`. For a user who must answer a second factor:
 *
 * 1. `send_auth_cookies` (only inside wp_signon(), marked by the
 *    `wp_authenticate` action) returns false, so the session cookie never
 *    leaves the server, and its session token is remembered;
 * 2. `wp_login` destroys that session token (a cookie that leaked anyway is
 *    dead), clears the auth cookies, stores a PendingLogin and redirects to
 *    wp-login.php?action=lw_firewall_2fa;
 * 3. the challenge screen (ChallengeController) accepts a TOTP code, a recovery code or a passkey;
 *    on success the pending record is consumed, then wp_set_auth_cookie(),
 *    wp_set_current_user() and `lw_firewall_2fa_passed` ( $user_id, $method ).
 *
 * `wp_login` is deliberately NOT fired again after the second factor: it
 * would re-enter this interceptor and repeat every other plugin's login side
 * effects. Hook `lw_firewall_2fa_passed` for "the login is now complete".
 */
final class LoginInterceptor {

	/**
	 * Whether a wp_signon() is in progress in this request.
	 *
	 * @var bool
	 */
	private bool $in_signon = false;

	/**
	 * The challenge screen handler.
	 *
	 * @var ChallengeController
	 */
	private ChallengeController $challenge;

	/**
	 * Session tokens withheld by send_auth_cookies, per user.
	 *
	 * @var array<int, string[]>
	 */
	private array $held = array();

	/**
	 * Halts the request after a redirect or a rendered screen.
	 *
	 * @var \Closure
	 */
	private \Closure $halt;

	/**
	 * Constructor (every collaborator is replaceable for tests).
	 *
	 * @param PendingLogin|null         $pending  Pending-login store.
	 * @param SecondFactorVerifier|null $verifier Factor checks.
	 * @param ChallengePage|null        $page     Screen.
	 * @param RequestContext|null       $context  Request kind.
	 * @param \Closure|null             $halt     Ends the request; null = exit.
	 */
	public function __construct(
		private readonly ?PendingLogin $pending = null,
		?SecondFactorVerifier $verifier = null,
		?ChallengePage $page = null,
		private readonly ?RequestContext $context = null,
		?\Closure $halt = null
	) {
		$this->halt      = $halt ?? static function (): void {
			exit;
		};
		$this->challenge = new ChallengeController( $this->pending(), $verifier ?? new SecondFactorVerifier(), $page ?? new ChallengePage(), $this->halt );
	}

	/**
	 * Register the hooks.
	 */
	public function register(): void {
		add_action( 'wp_authenticate', array( $this, 'on_signon_start' ), 0, 0 );
		add_filter( 'send_auth_cookies', array( $this, 'filter_send_cookies' ), 99, 6 );
		add_action( 'wp_login', array( $this, 'on_wp_login' ), 1, 2 );
		add_action( 'login_form_' . ChallengePage::ACTION, array( $this, 'handle_action' ) );
	}

	/**
	 * `wp_authenticate` action: fired by wp_signon() only.
	 */
	public function on_signon_start(): void {
		$this->in_signon = true;
	}

	/**
	 * `send_auth_cookies` filter: withhold the session cookie of a login that
	 * still needs its second factor.
	 *
	 * @param mixed $send       Current answer.
	 * @param mixed $expire     Cookie expiry (unused).
	 * @param mixed $expiration Session expiry (unused).
	 * @param mixed $user_id    User the cookie is for.
	 * @param mixed $scheme     Cookie scheme (unused).
	 * @param mixed $token      Session token.
	 * @return mixed
	 */
	public function filter_send_cookies( $send, $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed
		if ( ! $this->in_signon || $this->challenge->is_completing() || ! is_numeric( $user_id ) || (int) $user_id <= 0 ) {
			return $send;
		}

		$user = get_userdata( (int) $user_id );
		if ( ! $user instanceof WP_User || ! $this->intercepts( $user ) ) {
			return $send;
		}

		if ( is_string( $token ) && '' !== $token ) {
			$this->held[ (int) $user_id ][] = $token;
		}

		return false;
	}

	/**
	 * `wp_login` action: turn the finished password login into a pending one.
	 *
	 * @param string  $login User login (unused).
	 * @param WP_User $user  User who passed the password check.
	 */
	public function on_wp_login( string $login, WP_User $user ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed
		if ( $this->challenge->is_completing() || ! $this->intercepts( $user ) ) {
			return;
		}

		$this->discard_sessions( (int) $user->ID );
		wp_clear_auth_cookie();

		$token = $this->pending()->create( (int) $user->ID, LoginRequest::remember(), LoginRequest::redirect_to() );
		$this->redirect( ChallengePage::url( $token ) );
	}

	/**
	 * Whether this login is held for a second factor (interactive requests only).
	 *
	 * @param WP_User $user User.
	 */
	public function intercepts( WP_User $user ): bool {
		return $this->context()->is_interactive() && $this->should_challenge( $user );
	}

	/**
	 * Whether the user must answer a second factor.
	 *
	 * @param WP_User $user User.
	 */
	public function should_challenge( WP_User $user ): bool {
		return ( new UserFactors( (int) $user->ID ) )->has_any();
	}

	/**
	 * `login_form_lw_firewall_2fa`: show the screen or check an answer.
	 */
	public function handle_action(): void {
		$this->challenge->handle();
	}

	/**
	 * Destroy the session tokens withheld during this signon.
	 *
	 * @param int $user_id User.
	 */
	private function discard_sessions( int $user_id ): void {
		if ( empty( $this->held[ $user_id ] ) || ! class_exists( WP_Session_Tokens::class ) ) {
			return;
		}

		$sessions = WP_Session_Tokens::get_instance( $user_id );
		foreach ( $this->held[ $user_id ] as $token ) {
			$sessions->destroy( $token );
		}
		unset( $this->held[ $user_id ] );
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

	/**
	 * Pending-login store.
	 */
	private function pending(): PendingLogin {
		return $this->pending ?? new PendingLogin();
	}

	/**
	 * Request kind.
	 */
	private function context(): RequestContext {
		return $this->context ?? new RequestContext();
	}
}
