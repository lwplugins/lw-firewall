<?php
/**
 * Public shape of a user's two-factor state.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Rest;

use LightweightPlugins\Firewall\TwoFactor\Enforcement;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The only place that turns stored factors into a response: no secret, hash,
 * credential id, public key or user handle ever leaves through it.
 */
final class FactorStatus {

	/**
	 * Status of a user.
	 *
	 * @param WP_User          $user        User.
	 * @param Enforcement|null $enforcement Requirement rules; null = default.
	 * @return array{totp: bool, recovery_left: int, passkeys: array<int, array{id: string, label: string, created_at: int, last_used_at: int}>, required: bool, grace_ends_at: int}
	 */
	public static function of( WP_User $user, ?Enforcement $enforcement = null ): array {
		$factors     = new UserFactors( (int) $user->ID );
		$enforcement = $enforcement ?? new Enforcement();
		$required    = $enforcement->is_required( $user );

		return array(
			'totp'          => $factors->has_totp_record(),
			'recovery_left' => count( $factors->recovery_hashes() ),
			'passkeys'      => array_map( array( self::class, 'passkey' ), $factors->passkeys() ),
			'required'      => $required,
			'grace_ends_at' => $required ? $enforcement->grace_ends_at( $user ) : 0,
		);
	}

	/**
	 * Public fields of one passkey.
	 *
	 * @param PasskeyRecord $record Record.
	 * @return array{id: string, label: string, created_at: int, last_used_at: int}
	 */
	public static function passkey( PasskeyRecord $record ): array {
		return array(
			'id'           => $record->id,
			'label'        => $record->label,
			'created_at'   => $record->created_at,
			'last_used_at' => $record->last_used_at,
		);
	}
}
