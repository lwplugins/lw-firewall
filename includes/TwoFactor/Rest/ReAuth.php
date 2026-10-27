<?php
/**
 * Re-authentication of a sensitive profile action.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Rest;

use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\Totp;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;
use WP_Error;
use WP_REST_Request;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A logged-in cookie alone must not be enough to remove or change a second
 * factor: the request carries the account's current password
 * (`current_password`) or a fresh TOTP code (`code`, replay-guarded like at
 * login). Every attempt claims a slot of the account's FailureThrottle before
 * it is checked (the same budget as the login step), so a stolen session
 * cannot guess its way through either.
 */
final class ReAuth {

	public const REQUIRED_CODE = 'lwfw_2fa_reauth_required';
	public const FAILED_CODE   = 'lwfw_2fa_reauth_failed';
	public const BLOCKED_CODE  = 'lwfw_2fa_reauth_blocked';

	/**
	 * Longest accepted password (bcrypt reads 72 bytes; this caps hashing work).
	 */
	private const PASSWORD_MAX = 4096;

	/**
	 * Constructor.
	 *
	 * @param FailureThrottle|null $throttle Per-account answer budget.
	 * @param \Closure|null        $clock    Returns the current Unix time (tests); null = time().
	 */
	public function __construct( private readonly ?FailureThrottle $throttle = null, private readonly ?\Closure $clock = null ) {}

	/**
	 * Check the request's proof for this user.
	 *
	 * @param WP_User         $user       Account whose password or code is asked.
	 * @param WP_REST_Request $request    Request.
	 * @param bool            $allow_code Whether a TOTP code may stand in for the password.
	 * @return bool|WP_Error True, or the refusal.
	 */
	public function check( WP_User $user, WP_REST_Request $request, bool $allow_code = true ): bool|WP_Error {
		$password = self::param( $request, 'current_password' );
		$code     = $allow_code ? self::param( $request, 'code' ) : '';
		if ( '' === $password && '' === $code ) {
			return new WP_Error( self::REQUIRED_CODE, self::required_message( $allow_code ), array( 'status' => 403 ) );
		}

		$id       = (int) $user->ID;
		$throttle = $this->throttle ?? new FailureThrottle();
		if ( $throttle->is_blocked( $id ) || ! $throttle->claim( $id ) ) {
			return new WP_Error( self::BLOCKED_CODE, __( 'Too many wrong attempts. Wait 15 minutes and try again.', 'lw-firewall' ), array( 'status' => 429 ) );
		}

		if ( $this->accepts( $user, $password, $code ) ) {
			$throttle->succeeded( $id );
			return true;
		}

		$throttle->record_failure( $id );

		return new WP_Error( self::FAILED_CODE, __( 'The password or code is not correct.', 'lw-firewall' ), array( 'status' => 403 ) );
	}

	/**
	 * Whether the password (preferred) or the TOTP code is right.
	 *
	 * @param WP_User $user     Account.
	 * @param string  $password Password ('' = none).
	 * @param string  $code     TOTP code ('' = none).
	 */
	private function accepts( WP_User $user, string $password, string $code ): bool {
		if ( '' !== $password ) {
			return strlen( $password ) <= self::PASSWORD_MAX && wp_check_password( $password, (string) $user->user_pass, (int) $user->ID );
		}

		$factors = new UserFactors( (int) $user->ID );
		$secret  = $factors->totp_secret();
		$step    = null === $secret ? null : Totp::verify( $secret, $code, $factors->totp_last_step(), $this->now() );
		if ( null === $step ) {
			return false;
		}
		$factors->mark_totp_step( $step );

		return true;
	}

	/**
	 * A string parameter, unmodified ('' when absent).
	 *
	 * @param WP_REST_Request $request Request.
	 * @param string          $name    Parameter.
	 */
	private static function param( WP_REST_Request $request, string $name ): string {
		$value = $request->get_param( $name );

		return is_string( $value ) ? $value : '';
	}

	/**
	 * Text of the "proof required" refusal.
	 *
	 * @param bool $allow_code Whether a code is accepted.
	 */
	private static function required_message( bool $allow_code ): string {
		return $allow_code
			? __( 'Confirm it with your password or a code from your authenticator app.', 'lw-firewall' )
			: __( 'Confirm it with your password.', 'lw-firewall' );
	}

	/**
	 * Current Unix time.
	 */
	private function now(): int {
		return null === $this->clock ? time() : (int) ( $this->clock )();
	}
}
