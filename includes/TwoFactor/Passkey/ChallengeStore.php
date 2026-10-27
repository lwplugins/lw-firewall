<?php
/**
 * Single-use WebAuthn challenges, kept server side.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Passkey;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The browser only ever holds an opaque key; the challenge bytes, their purpose
 * and the bound user stay in a short-lived transient that is consumed on read.
 */
final class ChallengeStore {

	private const PREFIX = 'lwfw_pk_';

	/**
	 * Lifetime in seconds (matches the ceremony timeout).
	 */
	public const TTL = 120;

	/**
	 * Store a challenge.
	 *
	 * @param string $purpose       Ceremony name (e.g. "register", "assert").
	 * @param string $challenge_bin Raw challenge bytes.
	 * @param int    $user_id       Bound user, 0 = none.
	 * @return string 32 char hex key.
	 */
	public static function put( string $purpose, string $challenge_bin, int $user_id = 0 ): string {
		$key = bin2hex( random_bytes( 16 ) );

		// Hex, not raw bytes: the options table would strip invalid UTF-8.
		set_transient(
			self::PREFIX . $key,
			array(
				'purpose'   => $purpose,
				'challenge' => bin2hex( $challenge_bin ),
				'user_id'   => $user_id,
			),
			self::TTL
		);

		return $key;
	}

	/**
	 * Fetch and delete a challenge (single use, also on a purpose mismatch).
	 *
	 * @param string $key     Key from put().
	 * @param string $purpose Expected ceremony.
	 * @return array{challenge: string, user_id: int}|null
	 */
	public static function take( string $key, string $purpose ): ?array {
		if ( 1 !== preg_match( '/^[0-9a-f]{32}$/D', $key ) ) {
			return null;
		}

		$name = self::PREFIX . $key;
		$data = get_transient( $name );
		if ( ! is_array( $data ) ) {
			return null;
		}

		// Only the request whose delete removed the row may use it (parallel replay guard).
		if ( ! delete_transient( $name ) ) {
			return null;
		}

		if ( ! isset( $data['purpose'], $data['challenge'], $data['user_id'] )
			|| ! is_string( $data['purpose'] ) || ! is_string( $data['challenge'] ) || ! is_int( $data['user_id'] )
			|| ! hash_equals( $data['purpose'], $purpose )
			|| 1 !== preg_match( '/^(?:[0-9a-f]{2})+$/D', $data['challenge'] )
		) {
			return null;
		}

		return array(
			'challenge' => (string) hex2bin( $data['challenge'] ),
			'user_id'   => $data['user_id'],
		);
	}
}
