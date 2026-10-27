<?php
/**
 * Issues and prunes a user's recovery codes.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Recovery codes exist exactly while the account has a second factor: the
 * first factor of any kind issues them (so a passkey-only account still has a
 * way in where WebAuthn is unavailable), removing the last factor drops them.
 * The plain codes are returned once and never stored.
 */
final class RecoveryIssuer {

	/**
	 * Codes per issue.
	 */
	public const COUNT = 10;

	/**
	 * Issue codes when the account has none.
	 *
	 * @param UserFactors $factors Store.
	 * @return string[] Plain codes (empty when the existing ones stay).
	 */
	public static function ensure( UserFactors $factors ): array {
		return array() === $factors->recovery_hashes() ? self::regenerate( $factors ) : array();
	}

	/**
	 * Replace the codes with a fresh set.
	 *
	 * @param UserFactors $factors Store.
	 * @return string[] Plain codes.
	 */
	public static function regenerate( UserFactors $factors ): array {
		$codes = RecoveryCodes::generate( self::COUNT );
		$factors->set_recovery( $codes['hashes'] );

		return $codes['plain'];
	}

	/**
	 * Drop the codes once no factor is left.
	 *
	 * @param UserFactors $factors Store.
	 */
	public static function prune( UserFactors $factors ): void {
		if ( ! $factors->has_any() && array() !== $factors->recovery_hashes() ) {
			$factors->set_recovery( array() );
		}
	}
}
