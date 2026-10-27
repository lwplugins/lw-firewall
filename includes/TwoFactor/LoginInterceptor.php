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
 * 1. `send_auth_cookies` (only inside wp_signon(), see SignonTracker)
 *    returns false, so the session cookie never leaves the server; the
 *    session token of every auth cookie issued in the request is noted
 *    (`set_auth_cookie` / `set_logged_in_cookie`), in wp_signon() or not;
 * 2. `wp_login` destroys those session tokens (a cookie that leaked anyway,
 *    e.g. from a custom login handler, is dead), clears the auth cookies,
 *    stores a PendingLogin and redirects to wp-login.php?action=lw_firewall_2fa;
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
	 * The challenge screen handler.
	 *
	 * @var ChallengeController
	 */
	private ChallengeController $challenge;

	/**
	 * Session tokens issued in this request, per user (withheld or not).
	 *
	 * @var array<int, string[]>
	 */
	private array $issued = array();

	/**
	 * Halts the request after a redirect or a rendered screen.
	 *
	 * @var \Closure
	 */
	private \Closure $halt;

	/**
	 * Trusted-device cookie.
	 *
	 * @var RememberDevice
	 */
	private RememberDevice $remember;

	/**
	 * The running wp_signon().
	 *
	 * @var SignonTracker
	 */
	private SignonTracker $signon;

	/**
	 * Per-account failure cap.
	 *
	 * @var FailureThrottle
	 */
	private FailureThrottle $throttle;

	/**
	 * Screen.
	 *
	 * @var ChallengePage
	 */
	private ChallengePage $page;

	/**
	 * Constructor (every collaborator is replaceable for tests).
	 *
	 * @param PendingLogin|null         $pending  Pending-login store.
	 * @param SecondFactorVerifier|null $verifier Factor checks.
	 * @param ChallengePage|null        $page     Screen.
	 * @param RequestContext|null       $context  Request kind.
	 * @param \Closure|null             $halt     Ends the request; null = exit.
	 * @param SignonTracker|null        $signon   Shared sign-on state (registered by TwoFactorModule).
	 * @param FailureThrottle|null      $throttle Per-account failure cap.
	 * @param RememberDevice|null       $remember Trusted-device cookie.
	 */
	public function __construct(
		private readonly ?PendingLogin $pending = null,
		?SecondFactorVerifier $verifier = null,
		?ChallengePage $page = null,
		private readonly ?RequestContext $context = null,
		?\Closure $halt = null,
		?SignonTracker $signon = null,
		?FailureThrottle $throttle = null,
		?RememberDevice $remember = null
	) {
		$this->remember  = $remember ?? new RememberDevice();
		$this->halt      = $halt ?? static function (): void {
			exit;
		};
		$this->signon    = $signon ?? new SignonTracker();
		$this->throttle  = $throttle ?? new FailureThrottle();
		$this->page      = $page ?? new ChallengePage();
		$this->challenge = new ChallengeController( $this->pending(), $verifier ?? new SecondFactorVerifier(), $this->page, $this->halt, $this->throttle, $this->remember );
	}

	/**
	 * Register the hooks.
	 */
	public function register(): void {
		add_filter( 'send_auth_cookies', array( $this, 'filter_send_cookies' ), PHP_INT_MAX, 6 );
		add_action( 'set_auth_cookie', array( $this, 'capture_cookie' ), 10, 6 );
		add_action( 'set_logged_in_cookie', array( $this, 'capture_cookie' ), 10, 6 );
		add_action( 'wp_login', array( $this, 'on_wp_login' ), 1, 2 );
		add_action( 'login_form_' . ChallengePage::ACTION, array( $this, 'handle_action' ) );
	}

	/**
	 * `set_auth_cookie` / `set_logged_in_cookie`: note the session token of
	 * every auth cookie issued in this request, inside wp_signon() or not, so
	 * on_wp_login() can kill the session even when the cookie already left.
	 *
	 * @param mixed $cookie     Cookie value (unused).
	 * @param mixed $expire     Cookie expiry (unused).
	 * @param mixed $expiration Session expiry (unused).
	 * @param mixed $user_id    User the cookie is for.
	 * @param mixed $scheme     Cookie scheme (unused).
	 * @param mixed $token      Session token.
	 */
	public function capture_cookie( $cookie = '', $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed
		$this->note_token( $user_id, $token );
	}

	/**
	 * `send_auth_cookies` filter: inside wp_signon(), withhold the session
	 * cookie of a login that still needs its second factor.
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
		$this->note_token( $user_id, $token );
		if ( ! $this->signon->in_progress() || $this->challenge->is_completing() || ! is_numeric( $user_id ) || (int) $user_id <= 0 ) {
			return $send;
		}

		$user = get_userdata( (int) $user_id );

		return $user instanceof WP_User && $this->intercepts( $user ) ? false : $send;
	}

	/**
	 * `wp_login` action: turn the finished password login into a pending one.
	 *
	 * Tolerates third-party calls with one argument or a non-user second one.
	 *
	 * @param mixed $login User login (unused).
	 * @param mixed $user  User who passed the password check.
	 */
	public function on_wp_login( $login = '', $user = null ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundBeforeLastUsed
		if ( ! $user instanceof WP_User || $this->challenge->is_completing() || ! $this->intercepts( $user ) ) {
			return;
		}

		$id = (int) $user->ID;
		$this->discard_sessions( $id );
		wp_clear_auth_cookie();

		if ( $this->throttle->is_blocked( $id ) ) {
			$this->page->render_throttled();
			( $this->halt )();
			return;
		}

		$remember = $this->signon->remember() ?? LoginRequest::remember();
		$secure   = $this->signon->secure() ?? is_ssl();
		$token    = $this->pending()->create( $id, $remember, LoginRequest::redirect_to(), $secure );
		$this->redirect( ChallengePage::url( $token ) );
	}

	/**
	 * Whether this login is held for a second factor: interactive requests
	 * only, and not core's cookie re-auth of a session that already passed.
	 *
	 * @param WP_User $user User.
	 */
	public function intercepts( WP_User $user ): bool {
		if ( ! $this->context()->is_interactive() || ( (int) $user->ID > 0 && $this->signon->cookie_user() === (int) $user->ID ) ) {
			return false;
		}

		return $this->should_challenge( $user );
	}

	/**
	 * Whether the user must answer a second factor.
	 *
	 * A remembered device only skips the challenge of a user who HAS factors;
	 * it never stands in for forced enrollment (role enforcement), which
	 * looks at has_any() on its own.
	 *
	 * @param WP_User $user User.
	 */
	public function should_challenge( WP_User $user ): bool {
		return ( new UserFactors( (int) $user->ID ) )->has_any() && ! $this->remember->is_valid( (int) $user->ID );
	}

	/**
	 * `login_form_lw_firewall_2fa`: show the screen or check an answer.
	 */
	public function handle_action(): void {
		$this->challenge->handle();
	}

	/**
	 * Remember a session token issued in this request.
	 *
	 * @param mixed $user_id User.
	 * @param mixed $token   Session token.
	 */
	private function note_token( $user_id, $token ): void {
		if ( $this->challenge->is_completing() || ! is_numeric( $user_id ) || (int) $user_id <= 0 || ! is_string( $token ) || '' === $token ) {
			return;
		}
		if ( ! in_array( $token, $this->issued[ (int) $user_id ] ?? array(), true ) ) {
			$this->issued[ (int) $user_id ][] = $token;
		}
	}

	/**
	 * Destroy every session token issued for the user in this request.
	 *
	 * @param int $user_id User.
	 */
	private function discard_sessions( int $user_id ): void {
		if ( empty( $this->issued[ $user_id ] ) || ! class_exists( WP_Session_Tokens::class ) ) {
			return;
		}

		$sessions = WP_Session_Tokens::get_instance( $user_id );
		foreach ( $this->issued[ $user_id ] as $token ) {
			$sessions->destroy( $token );
		}
		unset( $this->issued[ $user_id ] );
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
