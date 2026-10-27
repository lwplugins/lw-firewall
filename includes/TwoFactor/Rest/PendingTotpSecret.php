<?php
/**
 * A TOTP secret shown on the profile but not yet confirmed.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Rest;

use LightweightPlugins\Firewall\TwoFactor\SecretBox;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One pending secret per user, sealed (SecretBox) in a transient for ten
 * minutes. The confirm step reads it from here, never from the request.
 */
final class PendingTotpSecret {

	/**
	 * Lifetime in seconds.
	 */
	public const TTL = 600;

	private const PREFIX = 'lwfw_2fa_totp_';

	/**
	 * Store (replace) the user's pending secret.
	 *
	 * @param int    $user_id    User.
	 * @param string $secret_b32 Base32 secret.
	 */
	public static function put( int $user_id, string $secret_b32 ): void {
		set_transient( self::PREFIX . $user_id, SecretBox::seal( $secret_b32 ), self::TTL );
	}

	/**
	 * The pending secret, or null when absent, expired or unreadable.
	 *
	 * @param int $user_id User.
	 */
	public static function get( int $user_id ): ?string {
		$sealed = get_transient( self::PREFIX . $user_id );

		return is_string( $sealed ) && '' !== $sealed ? SecretBox::open( $sealed ) : null;
	}

	/**
	 * Forget the pending secret.
	 *
	 * @param int $user_id User.
	 */
	public static function clear( int $user_id ): void {
		delete_transient( self::PREFIX . $user_id );
	}
}
