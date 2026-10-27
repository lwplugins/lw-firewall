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
use LightweightPlugins\Firewall\TwoFactor\Passkey\AssertionInput;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;
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
 * Public by design: there is no session before a login, so no REST nonce.
 * The single-use, server-side challenge (ChallengeStore, purpose
 * "assert_login", not bound to a user) is the CSRF defense: a forged request
 * cannot carry a signature over a challenge the victim's browser asked for.
 * A challenge issued for the second-factor screen is refused by the service.
 *
 * Rate limit: 20 requests per IP subject per 10 minutes on the request
 * storage. That storage fails open (Redis down = 1), which is acceptable
 * here: a passkey cannot be guessed (each answer is a signature over a fresh
 * challenge), so the limit is only flood protection, not a guessing budget.
 * For the same reason a failed passwordless answer is NOT counted into the
 * per-account FailureThrottle: anyone could send junk with a victim's
 * credential id and lock the victim out without knowing the password. It is
 * reported as `wp_login_failed` (per-IP lockouts) and logged.
 *
 * Success never runs wp_signon() (there is no password): the account's
 * FailureThrottle block and multisite spam flag are checked, then the
 * session is set and `wp_login` fired with LoginInterceptor::skip_once(), as
 * a user-verified passkey is already two factors. No remembered-device
 * cookie is issued or needed.
 */
final class PasskeyLoginController {

	/**
	 * Route base under the plugin namespace.
	 */
	public const BASE = '/passkey/login';

	/**
	 * Requests per IP subject per window.
	 */
	public const RATE_LIMIT = 20;

	/**
	 * Rate-limit window in seconds.
	 */
	public const RATE_WINDOW = 600;

	/**
	 * Storage key prefix of the per-IP counter.
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
	 * @param PasskeyService|null   $service  Passkey ceremonies.
	 * @param StorageInterface|null $storage  Rate-limit storage; null = the configured one.
	 * @param FailureThrottle|null  $throttle Per-account block (read only).
	 */
	public function __construct(
		private readonly ?PasskeyService $service = null,
		private readonly ?StorageInterface $storage = null,
		private readonly ?FailureThrottle $throttle = null
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
		register_rest_route(
			Routes::NAMESPACE,
			self::BASE . '/options',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'options' ),
				'permission_callback' => array( $this, 'rate_limit' ),
			)
		);
		register_rest_route(
			Routes::NAMESPACE,
			self::BASE . '/verify',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'verify' ),
				'permission_callback' => array( $this, 'rate_limit' ),
			)
		);
	}

	/**
	 * Permission callback: the per-IP flood limit (public routes otherwise).
	 *
	 * @return true|WP_Error
	 */
	public function rate_limit(): bool|WP_Error {
		$storage = $this->storage ?? lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		$count   = $storage->increment( self::RATE_PREFIX . IpSubject::of( IpDetector::get_ip() ), self::RATE_WINDOW );
		if ( $count <= self::RATE_LIMIT ) {
			return true;
		}

		return new WP_Error( self::RATE_CODE, __( 'Too many sign-in attempts. Wait a few minutes and try again.', 'lw-firewall' ), array( 'status' => 429 ) );
	}

	/**
	 * A discoverable assertion challenge.
	 *
	 * @return array{key: string, options: array<string, mixed>}|WP_Error
	 */
	public function options(): array|WP_Error {
		$out = $this->service()->assertion_options( null );
		if ( $out instanceof WP_Error ) {
			return new WP_Error( self::UNAVAIL_CODE, __( 'Passkey sign-in is not available right now. Sign in with your password.', 'lw-firewall' ), array( 'status' => 503 ) );
		}

		return $out;
	}

	/**
	 * Check the assertion and start the session.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{redirect: string}|WP_Error
	 */
	public function verify( WP_REST_Request $request ): array|WP_Error {
		$key        = $request->get_param( 'key' );
		$credential = self::credential( $request->get_param( 'credential' ) );
		$user_id    = $this->service()->verify_assertion( is_string( $key ) ? $key : '', $credential );
		$user       = is_int( $user_id ) ? get_userdata( $user_id ) : false;
		if ( ! $user instanceof WP_User ) {
			return $this->fail( $credential );
		}

		if ( $this->throttle()->is_blocked( (int) $user->ID ) || ( is_multisite() && is_user_spammy( $user ) ) ) {
			FailureLog::record( FailureLog::TWOFA_FAILED );
			return new WP_Error( self::BLOCKED_CODE, ChallengePage::throttled_message(), array( 'status' => 403 ) );
		}

		$this->sign_in( $user, (bool) filter_var( $request->get_param( 'remember' ), FILTER_VALIDATE_BOOLEAN ) );

		return array( 'redirect' => LoginRequest::destination( self::redirect_to( $request->get_param( 'redirect_to' ) ), $user ) );
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
	 * Refused assertion: report and log it, answer generically.
	 *
	 * @param array<string, string> $credential Submitted assertion.
	 */
	private function fail( array $credential ): WP_Error {
		$message = __( 'The passkey was not accepted. Try again or sign in with your password.', 'lw-firewall' );
		$input   = AssertionInput::parse( $credential );
		$owner   = null === $input ? null : UserFactors::find_user_by_credential( $input->credential_id );
		$account = null === $owner ? false : get_userdata( $owner );

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook: the per-IP and per-username brute-force counters count this attempt.
		do_action( 'wp_login_failed', $account instanceof WP_User ? $account->user_login : '', new WP_Error( self::ERROR_CODE, $message ) );
		FailureLog::record( FailureLog::PASSKEY_FAILED );

		return new WP_Error( self::ERROR_CODE, $message, array( 'status' => 400 ) );
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
}
