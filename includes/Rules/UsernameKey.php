<?php
/**
 * Normalised username keys for per-account login throttling.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pure: turns a typed login into the key its failures are counted under,
 * so "Admin", " admin " and "ADMIN" share one counter.
 */
final class UsernameKey {

	/**
	 * Longest login considered; anything longer is truncated before hashing.
	 */
	private const MAX_LENGTH = 200;

	/**
	 * Normalise a typed login: trimmed, lower-case, inner whitespace collapsed.
	 *
	 * @param string $login Typed login (username or email).
	 * @return string Empty when nothing is left.
	 */
	public static function normalize( string $login ): string {
		$login = trim( (string) preg_replace( '/\s+/u', ' ', $login ) );
		$login = function_exists( 'mb_strtolower' ) ? mb_strtolower( $login, 'UTF-8' ) : strtolower( $login );

		return substr( $login, 0, self::MAX_LENGTH );
	}

	/**
	 * The storage key fragment for a login.
	 *
	 * Hashed, so an arbitrary attacker-chosen username never becomes part of
	 * a storage key or file name.
	 *
	 * @param string $login Typed login.
	 * @return string 32 hex characters, or '' for an empty login.
	 */
	public static function hash( string $login ): string {
		$normal = self::normalize( $login );

		return '' === $normal ? '' : md5( $normal );
	}

	/**
	 * Whether a value looks like a key produced by hash().
	 *
	 * @param string $value Candidate.
	 * @return bool
	 */
	public static function is_hash( string $value ): bool {
		return 1 === preg_match( '/^[a-f0-9]{32}$/', $value );
	}
}
