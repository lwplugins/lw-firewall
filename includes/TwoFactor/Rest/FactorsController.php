<?php
/**
 * Two-factor self-service REST routes (TOTP, recovery codes, devices, admin reset).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Rest;

use LightweightPlugins\Firewall\Rest\Admin\Routes;
use LightweightPlugins\Firewall\TwoFactor\Enforcement;
use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\RecoveryIssuer;
use LightweightPlugins\Firewall\TwoFactor\Totp;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;
use WP_Error;
use WP_REST_Request;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Routes under lw-firewall/v1/2fa, used by the profile screen. Cookie
 * authentication: core turns a request without a valid X-WP-Nonce into a
 * logged-out one, which every permission callback refuses.
 *
 * - GET  /me, GET /users/{id} (edit_user): FactorStatus.
 * - POST /totp/begin (ReAuth) → { secret, uri }: the secret waits sealed in
 *   PendingTotpSecret.
 * - POST /totp/confirm ( code ) → { recovery_codes }: codes only on the first
 *   issue, shown once.
 * - DELETE /totp, POST /recovery/regenerate, POST /devices/forget: ReAuth
 *   (a factor proof once the account has one, see ReAuth);
 *   the last two announce UserFactors::CHANGED_ACTION ( 'regenerated',
 *   'recovery' ) / ( 'forgotten', 'devices' ), so FactorNotifier mails the owner.
 * - POST /users/{id}/reset: another user only, with the admin's own password.
 *
 * Passkey routes: PasskeysController.
 */
final class FactorsController {

	public const BASE = '/2fa';

	public const CODE_INVALID   = 'lwfw_2fa_code_invalid';
	public const CODE_EXPIRED   = 'lwfw_2fa_setup_expired';
	public const CODE_EXISTS    = 'lwfw_2fa_totp_exists';
	public const CODE_NO_FACTOR = 'lwfw_2fa_no_factor';
	public const CODE_NO_USER   = 'lwfw_2fa_no_user';

	/**
	 * Constructor (collaborators replaceable for tests).
	 *
	 * @param FailureThrottle|null $throttle    Re-auth budget.
	 * @param \Closure|null        $clock       Returns the current Unix time; null = time().
	 * @param Enforcement|null     $enforcement Requirement rules.
	 * @param PasskeyService|null  $passkeys    Passkey re-auth; null = default.
	 */
	public function __construct(
		private readonly ?FailureThrottle $throttle = null,
		private readonly ?\Closure $clock = null,
		private readonly ?Enforcement $enforcement = null,
		private readonly ?PasskeyService $passkeys = null
	) {}

	/**
	 * Hook the route registration.
	 */
	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register the routes.
	 */
	public function register_routes(): void {
		$user   = '/users/(?P<user_id>\d+)';
		$routes = array(
			array( '/me', 'GET', 'me', 'logged_in' ),
			array( '/totp/begin', 'POST', 'totp_begin', 'logged_in' ),
			array( '/totp/confirm', 'POST', 'totp_confirm', 'logged_in' ),
			array( '/totp', 'DELETE', 'totp_delete', 'logged_in' ),
			array( '/recovery/regenerate', 'POST', 'recovery_regenerate', 'logged_in' ),
			array( '/devices/forget', 'POST', 'devices_forget', 'logged_in' ),
			array( $user, 'GET', 'user_status', 'can_edit' ),
			array( $user . '/reset', 'POST', 'reset', 'can_reset' ),
		);
		foreach ( $routes as [ $route, $method, $callback, $permission ] ) {
			register_rest_route(
				Routes::NAMESPACE,
				self::BASE . $route,
				array(
					'methods'             => $method,
					'callback'            => array( $this, $callback ),
					'permission_callback' => array( self::class, $permission ),
				)
			);
		}
	}

	/**
	 * Permission: any logged-in user (acting on their own account).
	 *
	 * @return bool|WP_Error
	 */
	public static function logged_in(): bool|WP_Error {
		return is_user_logged_in() ? true : self::forbidden();
	}

	/**
	 * Permission: the current user may edit the route's user.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return bool|WP_Error
	 */
	public static function can_edit( WP_REST_Request $request ): bool|WP_Error {
		$id = absint( $request->get_param( 'user_id' ) );

		return is_user_logged_in() && $id > 0 && current_user_can( 'edit_user', $id ) ? true : self::forbidden();
	}

	/**
	 * Permission: may edit the route's user, and it is somebody else.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return bool|WP_Error
	 */
	public static function can_reset( WP_REST_Request $request ): bool|WP_Error {
		if ( absint( $request->get_param( 'user_id' ) ) === get_current_user_id() ) {
			return self::forbidden();
		}

		return self::can_edit( $request );
	}

	/**
	 * GET /me.
	 *
	 * For a user whose role requires a second factor this may start the grace
	 * clock (Enforcement::grace_ends_at() writes it once): intended, the same as
	 * the enrollment notice.
	 *
	 * @return array<string, mixed>
	 */
	public function me(): array {
		return FactorStatus::of( wp_get_current_user(), $this->enforcement );
	}

	/**
	 * GET /users/{id}.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array<string, mixed>|WP_Error
	 */
	public function user_status( WP_REST_Request $request ): array|WP_Error {
		$user = self::target( $request );

		return $user instanceof WP_User ? FactorStatus::of( $user, $this->enforcement ) : $user;
	}

	/**
	 * POST /totp/begin.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{secret: string, uri: string}|WP_Error
	 */
	public function totp_begin( WP_REST_Request $request ): array|WP_Error {
		$user    = wp_get_current_user();
		$factors = new UserFactors( (int) $user->ID );
		if ( $factors->has_totp_record() ) {
			return new WP_Error( self::CODE_EXISTS, __( 'An authenticator app is already set up. Remove it first to set up a new one.', 'lw-firewall' ), array( 'status' => 409 ) );
		}
		// Also for the first factor: a stolen session must not plant its own
		// authenticator. With a passkey already set up, only a factor proves it.
		$proof = $this->reauth()->check( $user, $request );
		if ( $proof instanceof WP_Error ) {
			return $proof;
		}

		$secret = Totp::generate_secret();
		PendingTotpSecret::put( (int) $user->ID, $secret );

		return array(
			'secret' => $secret,
			'uri'    => Totp::site_uri( $secret, (string) $user->user_login ),
		);
	}

	/**
	 * POST /totp/confirm.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{recovery_codes: string[]}|WP_Error
	 */
	public function totp_confirm( WP_REST_Request $request ): array|WP_Error {
		$id      = get_current_user_id();
		$factors = new UserFactors( $id );
		if ( $factors->has_totp_record() ) {
			return new WP_Error( self::CODE_EXISTS, __( 'An authenticator app is already set up.', 'lw-firewall' ), array( 'status' => 409 ) );
		}

		$secret = PendingTotpSecret::get( $id );
		if ( null === $secret ) {
			return new WP_Error( self::CODE_EXPIRED, __( 'The setup key expired. Start the setup again.', 'lw-firewall' ), array( 'status' => 400 ) );
		}

		$code = $request->get_param( 'code' );
		$step = Totp::verify( $secret, is_string( $code ) ? $code : '', 0, $this->now() );
		if ( null === $step ) {
			return new WP_Error( self::CODE_INVALID, __( 'The code is not correct. Check the time on your phone and try the newest code.', 'lw-firewall' ), array( 'status' => 400 ) );
		}

		PendingTotpSecret::clear( $id );
		$factors->save_totp( $secret );
		$factors->mark_totp_step( $step );

		return array( 'recovery_codes' => RecoveryIssuer::ensure( $factors ) );
	}

	/**
	 * DELETE /totp.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array<string, mixed>|WP_Error Status after the removal.
	 */
	public function totp_delete( WP_REST_Request $request ): array|WP_Error {
		$user  = wp_get_current_user();
		$proof = $this->reauth()->check( $user, $request );
		if ( $proof instanceof WP_Error ) {
			return $proof;
		}

		$factors = new UserFactors( (int) $user->ID );
		$factors->delete_totp();
		RecoveryIssuer::prune( $factors );

		return FactorStatus::of( $user, $this->enforcement );
	}

	/**
	 * POST /recovery/regenerate.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{recovery_codes: string[]}|WP_Error
	 */
	public function recovery_regenerate( WP_REST_Request $request ): array|WP_Error {
		$user    = wp_get_current_user();
		$factors = new UserFactors( (int) $user->ID );
		if ( ! $factors->has_any() ) {
			return new WP_Error( self::CODE_NO_FACTOR, __( 'Set up an authenticator app or a passkey first.', 'lw-firewall' ), array( 'status' => 409 ) );
		}

		$proof = $this->reauth()->check( $user, $request );
		if ( $proof instanceof WP_Error ) {
			return $proof;
		}

		$codes = RecoveryIssuer::regenerate( $factors );
		self::announce( (int) $user->ID, 'regenerated', 'recovery' );

		return array( 'recovery_codes' => $codes );
	}

	/**
	 * POST /devices/forget.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{forgotten: bool}|WP_Error
	 */
	public function devices_forget( WP_REST_Request $request ): array|WP_Error {
		$user  = wp_get_current_user();
		$proof = $this->reauth()->check( $user, $request );
		if ( $proof instanceof WP_Error ) {
			return $proof;
		}

		( new UserFactors( (int) $user->ID ) )->forget_devices();
		self::announce( (int) $user->ID, 'forgotten', 'devices' );

		return array( 'forgotten' => true );
	}

	/**
	 * POST /users/{id}/reset (the admin's own password, never a code).
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array<string, mixed>|WP_Error Status of the reset user.
	 */
	public function reset( WP_REST_Request $request ): array|WP_Error {
		$target = self::target( $request );
		if ( $target instanceof WP_Error ) {
			return $target;
		}

		$proof = $this->reauth()->check_password( wp_get_current_user(), $request );
		if ( $proof instanceof WP_Error ) {
			return $proof;
		}

		( new UserFactors( (int) $target->ID ) )->reset_all();
		PendingTotpSecret::clear( (int) $target->ID );

		return FactorStatus::of( $target, $this->enforcement );
	}

	/**
	 * The route's user.
	 *
	 * @param WP_REST_Request $request Request.
	 */
	private static function target( WP_REST_Request $request ): WP_User|WP_Error {
		$user = get_userdata( absint( $request->get_param( 'user_id' ) ) );

		return $user instanceof WP_User ? $user : new WP_Error( self::CODE_NO_USER, __( 'User not found.', 'lw-firewall' ), array( 'status' => 404 ) );
	}

	/**
	 * Tell the factor-change listeners (owner e-mail) about a security change.
	 *
	 * @param int    $user_id User.
	 * @param string $change  Change.
	 * @param string $factor  Subject.
	 */
	private static function announce( int $user_id, string $change, string $factor ): void {
		do_action( 'lw_firewall_2fa_factor_changed', $user_id, $change, $factor ); // Same as UserFactors::CHANGED_ACTION (a literal for the hook-name sniff).
	}

	/**
	 * Generic permission refusal.
	 */
	private static function forbidden(): WP_Error {
		return new WP_Error( 'rest_forbidden', __( 'Sorry, you are not allowed to do that.', 'lw-firewall' ), array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Re-authentication checker.
	 */
	private function reauth(): ReAuth {
		return new ReAuth( $this->throttle, $this->clock, $this->passkeys );
	}

	/**
	 * Current Unix time.
	 */
	private function now(): int {
		return null === $this->clock ? time() : (int) ( $this->clock )();
	}
}
