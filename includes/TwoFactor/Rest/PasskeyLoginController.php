<?php
/**
 * Passwordless passkey sign-in on the login page (public REST routes).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Rest;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\IpSubject;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rest\Admin\Routes;
use LightweightPlugins\Firewall\Storage\StorageInterface;
use LightweightPlugins\Firewall\TwoFactor\ChallengePage;
use LightweightPlugins\Firewall\TwoFactor\FailureLog;
use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\LoginInterceptor;
use LightweightPlugins\Firewall\TwoFactor\LoginRequest;
use LightweightPlugins\Firewall\TwoFactor\Passkey\OriginPolicy;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use WP_Error;
use WP_REST_Request;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * POST lw-firewall/v1/passkey/login/options → { key, options } (a discoverable
 * challenge, no allowCredentials); POST …/verify ( key, credential, remember,
 * redirect_to ) → { redirect }.
 *
 * Public: there is no session before a login, so no REST nonce. Login CSRF
 * (a cross-site page signing the victim's browser in to the attacker's
 * account, replacing any session it had) is stopped by three checks, not by
 * the challenge alone (it is not tied to a browser by itself):
 * 1. PasskeyLoginBinding: the challenge is bound to a SameSite=Strict
 *    HttpOnly cookie set with it, and verify needs that cookie;
 * 2. both routes accept only a JSON body (a cross-site form cannot send one
 *    without a CORS preflight);
 * 3. an Origin header, when sent, must be exactly one of OriginPolicy::origins().
 * A challenge issued for the second-factor screen is refused by the service.
 *
 * Rate limits: 30 options and 30 verify requests per IP subject per 10
 * minutes, separate counters on the request storage. That storage fails open
 * (Redis down = 1), which is acceptable: a passkey cannot be guessed (each
 * answer is a signature over a fresh challenge), so these are flood limits,
 * not a guessing budget. For the same reason a failed passwordless answer is
 * counted neither into the per-account FailureThrottle nor under the owner's
 * username: anyone could send junk with a victim's credential id and lock
 * the victim out without knowing the password. It is reported as
 * `wp_login_failed` with an empty username (per-IP counting only) and logged.
 *
 * Success never runs wp_signon() (there is no password), so the gates are
 * explicit: the FailureThrottle block, the multisite spam flag, and core's
 * `wp_authenticate_user` filter, where ban, approval, suspension and
 * membership plugins refuse an account (fail closed: a filter that checks
 * only a posted form refuses passkey sign-in too). The firewall's per-username
 * lockout (UserLockout) deliberately does not apply: it only exists against
 * password guessing, and honoring it would let someone who sprays wrong
 * passwords at a username lock its owner out of the passkey as well. Then
 * the session is set and `wp_login` fired with LoginInterceptor::skip_once(),
 * as a user-verified passkey is already two factors. No remembered-device
 * cookie is issued or needed.
 */
final class PasskeyLoginController {

	/**
	 * Route base under the plugin namespace.
	 */
	public const BASE = '/passkey/login';

	/**
	 * Requests per IP subject per window, per route.
	 */
	public const RATE_LIMIT = 30;

	/**
	 * Rate-limit window in seconds.
	 */
	public const RATE_WINDOW = 600;

	/**
	 * Storage key prefix of the per-IP counters (+ "o_" / "v_").
	 */
	public const RATE_PREFIX = 'lwfw_pkl_';

	/**
	 * Error codes (never the service's or the library's own codes).
	 */
	public const ERROR_CODE   = 'lwfw_pkl_failed';
	public const RATE_CODE    = 'lwfw_pkl_rate';
	public const BLOCKED_CODE = 'lwfw_pkl_blocked';
	public const UNAVAIL_CODE = 'lwfw_pkl_unavailable';

	/**
	 * Cap on the assertion's total field length (as on the challenge form).
	 */
	private const CREDENTIAL_MAX = 16384;

	/**
	 * Constructor (collaborators replaceable for tests).
	 *
	 * @param PasskeyService|null      $service  Passkey ceremonies.
	 * @param StorageInterface|null    $storage  Rate-limit storage; null = the configured one.
	 * @param FailureThrottle|null     $throttle Per-account block (read only).
	 * @param PasskeyLoginBinding|null $binding  Browser binding of the challenge.
	 */
	public function __construct(
		private readonly ?PasskeyService $service = null,
		private readonly ?StorageInterface $storage = null,
		private readonly ?FailureThrottle $throttle = null,
		private readonly ?PasskeyLoginBinding $binding = null
	) {}

	/**
	 * Hook the route registration.
	 */
	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register both routes.
	 */
	public function register_routes(): void {
		foreach ( array( 'options', 'verify' ) as $route ) {
			register_rest_route(
				Routes::NAMESPACE,
				self::BASE . '/' . $route,
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, $route ),
					'permission_callback' => array( $this, 'rate_limit_' . $route ),
				)
			);
		}
	}

	/**
	 * Permission callback of the options route (per-IP flood limit).
	 *
	 * @return true|WP_Error
	 */
	public function rate_limit_options(): bool|WP_Error {
		return $this->rate_limit( 'o_' );
	}

	/**
	 * Permission callback of the verify route (per-IP flood limit).
	 *
	 * @return true|WP_Error
	 */
	public function rate_limit_verify(): bool|WP_Error {
		return $this->rate_limit( 'v_' );
	}

	/**
	 * A discoverable assertion challenge, bound to this browser.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{key: string, options: array<string, mixed>}|WP_Error
	 */
	public function options( WP_REST_Request $request ): array|WP_Error {
		if ( ! self::same_site_json( $request ) ) {
			return new WP_Error( self::ERROR_CODE, self::failed_message(), array( 'status' => 400 ) );
		}

		$out = $this->service()->assertion_options( null );
		if ( $out instanceof WP_Error ) {
			return new WP_Error( self::UNAVAIL_CODE, __( 'Passkey sign-in is not available right now. Sign in with your password.', 'lw-firewall' ), array( 'status' => 503 ) );
		}
		$this->binding()->issue( $out['key'] );

		return $out;
	}

	/**
	 * Check the request, the binding and the assertion, then start the session.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{redirect: string}|WP_Error
	 */
	public function verify( WP_REST_Request $request ): array|WP_Error {
		$raw_key = $request->get_param( 'key' );
		$key     = is_string( $raw_key ) ? $raw_key : '';
		$bound   = $this->binding()->check( $key );
		if ( ! self::same_site_json( $request ) || ! $bound ) {
			return $this->fail();
		}

		$user_id = $this->service()->verify_assertion( $key, self::credential( $request->get_param( 'credential' ) ) );
		$user    = is_int( $user_id ) ? get_userdata( $user_id ) : false;
		if ( ! $user instanceof WP_User ) {
			return $this->fail();
		}

		$refusal = $this->refusal( $user );
		if ( null !== $refusal ) {
			return $refusal;
		}

		$this->sign_in( $user, (bool) filter_var( $request->get_param( 'remember' ), FILTER_VALIDATE_BOOLEAN ) );

		return array( 'redirect' => LoginRequest::destination( self::redirect_to( $request->get_param( 'redirect_to' ) ), $user ) );
	}

	/**
	 * Account-state gates of a verified user (null = may sign in).
	 *
	 * @param WP_User $user Verified user.
	 */
	private function refusal( WP_User $user ): ?WP_Error {
		if ( $this->throttle()->is_blocked( (int) $user->ID ) ) {
			FailureLog::record( FailureLog::TWOFA_FAILED );
			return new WP_Error( self::BLOCKED_CODE, ChallengePage::throttled_message(), array( 'status' => 403 ) );
		}

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook: ban, approval and membership plugins refuse an account here.
		$checked = apply_filters( 'wp_authenticate_user', $user, '' );
		$allowed = $checked instanceof WP_User && (int) $checked->ID === (int) $user->ID;
		if ( ! $allowed || ( is_multisite() && is_user_spammy( $user ) ) ) {
			FailureLog::record( FailureLog::PASSKEY_FAILED );
			return new WP_Error( self::BLOCKED_CODE, __( 'This account cannot sign in right now.', 'lw-firewall' ), array( 'status' => 403 ) );
		}

		return null;
	}

	/**
	 * Set the session and fire `wp_login` without the second-factor hold.
	 *
	 * @param WP_User $user     Verified user.
	 * @param bool    $remember Long-lived cookie.
	 */
	private function sign_in( WP_User $user, bool $remember ): void {
		$id = (int) $user->ID;
		wp_set_auth_cookie( $id, $remember );
		wp_set_current_user( $id );

		LoginInterceptor::skip_once( $id );
		try {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook: other plugins' login bookkeeping.
			do_action( 'wp_login', $user->user_login, $user );
		} finally {
			LoginInterceptor::cancel_skip();
		}
	}

	/**
	 * Refused request or assertion: report (IP level only), log, answer generically.
	 */
	private function fail(): WP_Error {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook: the per-IP brute-force counter counts this attempt; no username (see the class docblock).
		do_action( 'wp_login_failed', '', new WP_Error( self::ERROR_CODE, self::failed_message() ) );
		FailureLog::record( FailureLog::PASSKEY_FAILED );

		return new WP_Error( self::ERROR_CODE, self::failed_message(), array( 'status' => 400 ) );
	}

	/**
	 * Generic refusal text.
	 */
	private static function failed_message(): string {
		return __( 'The passkey was not accepted. Try again or sign in with your password.', 'lw-firewall' );
	}

	/**
	 * Per-IP flood limit of one route.
	 *
	 * @param string $scope Counter scope.
	 * @return true|WP_Error
	 */
	private function rate_limit( string $scope ): bool|WP_Error {
		$storage = $this->storage ?? lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		$count   = $storage->increment( self::RATE_PREFIX . $scope . IpSubject::of( IpDetector::get_ip() ), self::RATE_WINDOW );
		if ( $count <= self::RATE_LIMIT ) {
			return true;
		}

		return new WP_Error( self::RATE_CODE, __( 'Too many sign-in attempts. Wait a few minutes and try again.', 'lw-firewall' ), array( 'status' => 429 ) );
	}

	/**
	 * A JSON body, and an Origin header (when sent) that is exactly this site's.
	 *
	 * @param WP_REST_Request $request Request.
	 */
	private static function same_site_json( WP_REST_Request $request ): bool {
		if ( ! $request->is_json_content_type() ) {
			return false;
		}

		$origin = $request->get_header( 'origin' );

		return null === $origin || '' === $origin || in_array( $origin, OriginPolicy::origins(), true );
	}

	/**
	 * The assertion's base64url string fields (size-capped).
	 *
	 * @param mixed $raw Request value.
	 * @return array<string, string>
	 */
	private static function credential( $raw ): array {
		$fields = LoginRequest::passkey_fields( $raw );

		return array_sum( array_map( 'strlen', $fields ) ) > self::CREDENTIAL_MAX ? array() : $fields;
	}

	/**
	 * Requested redirect, validated to this site ('' = default).
	 *
	 * @param mixed $raw Request value.
	 */
	private static function redirect_to( $raw ): string {
		$url = is_string( $raw ) ? trim( sanitize_url( $raw ) ) : '';

		return '' === $url ? '' : (string) wp_validate_redirect( $url, admin_url() );
	}

	/**
	 * Passkey ceremonies.
	 */
	private function service(): PasskeyService {
		return $this->service ?? new PasskeyService();
	}

	/**
	 * Per-account block.
	 */
	private function throttle(): FailureThrottle {
		return $this->throttle ?? new FailureThrottle();
	}

	/**
	 * Browser binding.
	 */
	private function binding(): PasskeyLoginBinding {
		return $this->binding ?? new PasskeyLoginBinding();
	}
}
