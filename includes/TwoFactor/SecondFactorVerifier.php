<?php
/**
 * Checks a submitted second factor against a user's enrolled factors.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\Passkey\WebAuthnFactory;
use WP_Error;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One method per factor; each marks what it used (TOTP step, recovery code,
 * passkey counter) so an answer is never accepted twice.
 */
final class SecondFactorVerifier {

	public const TOTP     = 'totp';
	public const RECOVERY = 'recovery';
	public const PASSKEY  = 'passkey';

	/**
	 * Constructor.
	 *
	 * @param PasskeyService|null $passkeys Passkey ceremonies; null = default service.
	 * @param \Closure|null       $clock    Returns the current Unix time (tests); null = time().
	 */
	public function __construct( private readonly ?PasskeyService $passkeys = null, private readonly ?\Closure $clock = null ) {}

	/**
	 * Whether the user can answer with this method.
	 *
	 * @param int    $user_id User.
	 * @param string $method  One of the method constants.
	 */
	public function offers( int $user_id, string $method ): bool {
		$factors = new UserFactors( $user_id );

		return match ( $method ) {
			self::TOTP     => $factors->has_totp(),
			self::RECOVERY => array() !== $factors->recovery_hashes(),
			self::PASSKEY  => array() !== $factors->passkeys() && WebAuthnFactory::available(),
			default        => false,
		};
	}

	/**
	 * A TOTP code; the accepted step is stored so the code cannot be replayed.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Submitted code.
	 */
	public function verify_totp( int $user_id, string $code ): bool {
		$factors = new UserFactors( $user_id );
		$secret  = $factors->totp_secret();
		if ( null === $secret ) {
			return false;
		}

		$step = Totp::verify( $secret, $code, $factors->totp_last_step(), $this->now() );
		if ( null === $step ) {
			return false;
		}

		$factors->mark_totp_step( $step );

		return true;
	}

	/**
	 * The code that confirms a new, not yet stored TOTP secret.
	 *
	 * @param string $secret Base32 secret being enrolled.
	 * @param string $code   Submitted code.
	 * @return int|null Accepted time step (store it as the replay guard), or null.
	 */
	public function verify_enrollment( string $secret, string $code ): ?int {
		return Totp::verify( $secret, $code, 0, $this->now() );
	}

	/**
	 * A recovery code; a match is removed from the user's list.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Submitted code.
	 */
	public function verify_recovery( int $user_id, string $code ): bool {
		$factors   = new UserFactors( $user_id );
		$remaining = RecoveryCodes::consume( $code, $factors->recovery_hashes() );
		if ( null === $remaining ) {
			return false;
		}

		$factors->set_recovery( $remaining );

		return true;
	}

	/**
	 * Options for the passkey button, or null when the user cannot use one.
	 *
	 * @param WP_User $user Pending user.
	 * @return array{key: string, options: array<string, mixed>}|null
	 */
	public function passkey_options( WP_User $user ): ?array {
		if ( ! $this->offers( (int) $user->ID, self::PASSKEY ) ) {
			return null;
		}

		$result = $this->passkeys()->assertion_options( $user );

		return $result instanceof WP_Error ? null : $result;
	}

	/**
	 * A passkey assertion against the challenge stored for this pending login.
	 *
	 * The challenge key comes from the server-side pending record, never from
	 * the request, and the assertion must belong to exactly this user.
	 *
	 * @param int                  $user_id    Pending user.
	 * @param string               $key        Challenge key from the pending record.
	 * @param array<string, mixed> $credential Browser assertion.
	 */
	public function verify_passkey( int $user_id, string $key, array $credential ): bool {
		if ( '' === $key || $user_id <= 0 ) {
			return false;
		}

		return $user_id === $this->passkeys()->verify_assertion( $key, $credential, $user_id );
	}

	/**
	 * Passkey service.
	 */
	private function passkeys(): PasskeyService {
		return $this->passkeys ?? new PasskeyService();
	}

	/**
	 * Current Unix time.
	 */
	private function now(): int {
		return null === $this->clock ? time() : (int) ( $this->clock )();
	}
}
