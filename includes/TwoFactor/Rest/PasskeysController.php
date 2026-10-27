<?php
/**
 * Passkey self-service REST routes (register, remove).
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
use LightweightPlugins\Firewall\TwoFactor\UserFactors;
use WP_Error;
use WP_REST_Request;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Routes under lw-firewall/v1/2fa/passkeys for the logged-in user:
 *
 * - POST /begin → { key, options } (ReAuth first: a new passkey also signs in
 *   without a password, so a stolen session must not be able to plant one);
 * - POST /finish ( key, credential { clientDataJSON, attestationObject },
 *   label ) → { passkey, recovery_codes } (codes on the first passkey of an
 *   account without codes, shown once);
 * - DELETE /{id} (ReAuth) → FactorStatus.
 *
 * The ceremonies (user verification, origin policy, challenge binding) are
 * PasskeyService's; nothing here touches the WebAuthn data itself.
 */
final class PasskeysController {

	public const CODE_REJECTED    = 'lwfw_2fa_passkey_rejected';
	public const CODE_UNKNOWN     = 'lwfw_2fa_passkey_unknown';
	public const CODE_UNAVAILABLE = 'lwfw_2fa_passkey_unavailable';

	/**
	 * Cap on the registration response's total field length.
	 */
	private const CREDENTIAL_MAX = 65536;

	/**
	 * Constructor (collaborators replaceable for tests).
	 *
	 * @param PasskeyService|null  $service  Passkey ceremonies.
	 * @param FailureThrottle|null $throttle Re-auth budget.
	 * @param \Closure|null        $clock    Returns the current Unix time; null = time().
	 * @param Enforcement|null     $enforcement Requirement rules.
	 */
	public function __construct(
		private readonly ?PasskeyService $service = null,
		private readonly ?FailureThrottle $throttle = null,
		private readonly ?\Closure $clock = null,
		private readonly ?Enforcement $enforcement = null
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
		$routes = array(
			array( '/begin', 'POST', 'begin' ),
			array( '/finish', 'POST', 'finish' ),
			array( '/(?P<id>[a-f0-9]{64})', 'DELETE', 'delete' ),
		);
		foreach ( $routes as [ $route, $method, $callback ] ) {
			register_rest_route(
				Routes::NAMESPACE,
				FactorsController::BASE . '/passkeys' . $route,
				array(
					'methods'             => $method,
					'callback'            => array( $this, $callback ),
					'permission_callback' => array( FactorsController::class, 'logged_in' ),
				)
			);
		}
	}

	/**
	 * POST /passkeys/begin.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{key: string, options: array<string, mixed>}|WP_Error
	 */
	public function begin( WP_REST_Request $request ): array|WP_Error {
		$user  = wp_get_current_user();
		$proof = $this->reauth()->check( $user, $request );
		if ( $proof instanceof WP_Error ) {
			return $proof;
		}

		$out = $this->service()->registration_options( $user );
		if ( $out instanceof WP_Error ) {
			return new WP_Error( self::CODE_UNAVAILABLE, __( 'Passkeys are not available on this site right now.', 'lw-firewall' ), array( 'status' => 503 ) );
		}

		return $out;
	}

	/**
	 * POST /passkeys/finish.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array{passkey: array<string, mixed>, recovery_codes: string[]}|WP_Error
	 */
	public function finish( WP_REST_Request $request ): array|WP_Error {
		$user    = wp_get_current_user();
		$factors = new UserFactors( (int) $user->ID );
		$first   = array() === $factors->passkeys();
		$fields  = self::credential( $request->get_param( 'credential' ) );
		$key     = $request->get_param( 'key' );
		$label   = $request->get_param( 'label' );

		$record = $this->service()->finish_registration(
			$user,
			is_string( $key ) ? $key : '',
			$fields['clientDataJSON'],
			$fields['attestationObject'],
			is_string( $label ) ? sanitize_text_field( $label ) : ''
		);
		if ( $record instanceof WP_Error ) {
			return new WP_Error( self::CODE_REJECTED, __( 'The passkey could not be added. Try again.', 'lw-firewall' ), array( 'status' => 400 ) );
		}

		return array(
			'passkey'        => FactorStatus::passkey( $record ),
			'recovery_codes' => $first ? RecoveryIssuer::ensure( $factors ) : array(),
		);
	}

	/**
	 * DELETE /passkeys/{id}.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array<string, mixed>|WP_Error Status after the removal.
	 */
	public function delete( WP_REST_Request $request ): array|WP_Error {
		$user  = wp_get_current_user();
		$proof = $this->reauth()->check( $user, $request );
		if ( $proof instanceof WP_Error ) {
			return $proof;
		}

		$id      = $request->get_param( 'id' );
		$factors = new UserFactors( (int) $user->ID );
		if ( ! is_string( $id ) || ! $factors->remove_passkey( $id ) ) {
			return new WP_Error( self::CODE_UNKNOWN, __( 'This passkey does not exist.', 'lw-firewall' ), array( 'status' => 404 ) );
		}
		RecoveryIssuer::prune( $factors );

		return FactorStatus::of( $user, $this->enforcement );
	}

	/**
	 * The registration response's two base64url fields (size-capped).
	 *
	 * @param mixed $raw Request value.
	 * @return array{clientDataJSON: string, attestationObject: string}
	 */
	private static function credential( $raw ): array {
		$out = array(
			'clientDataJSON'    => '',
			'attestationObject' => '',
		);
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		foreach ( array_keys( $out ) as $field ) {
			$value         = $raw[ $field ] ?? '';
			$out[ $field ] = is_string( $value ) && 1 === preg_match( '/^[A-Za-z0-9_-]*$/', $value ) ? $value : '';
		}

		return strlen( $out['clientDataJSON'] ) + strlen( $out['attestationObject'] ) > self::CREDENTIAL_MAX
			? array(
				'clientDataJSON'    => '',
				'attestationObject' => '',
			)
			: $out;
	}

	/**
	 * Passkey ceremonies.
	 */
	private function service(): PasskeyService {
		return $this->service ?? new PasskeyService();
	}

	/**
	 * Re-authentication checker.
	 */
	private function reauth(): ReAuth {
		return new ReAuth( $this->throttle, $this->clock );
	}
}
