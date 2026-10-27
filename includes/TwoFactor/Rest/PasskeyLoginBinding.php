<?php
/**
 * Binds a passwordless login challenge to the browser that asked for it.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Rest;

use LightweightPlugins\Firewall\TwoFactor\Passkey\ChallengeStore;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Login-CSRF defense: issuing a challenge also sets a random HttpOnly,
 * SameSite=Strict cookie, and only its SHA-256 is stored, next to the
 * challenge key (own transient, ChallengeStore stays untouched). The
 * verification needs the same cookie, so an assertion the attacker signed
 * over a challenge from THEIR browser cannot be replayed through the victim's
 * browser: the victim's cookie is bound to another challenge, or missing.
 * Each check spends the binding and clears the cookie.
 */
final class PasskeyLoginBinding {

	/**
	 * Cookie name.
	 */
	public const COOKIE = 'lwfw_pk_bind';

	/**
	 * Lifetime in seconds (the challenge lifetime).
	 */
	public const TTL = ChallengeStore::TTL;

	/**
	 * Transient prefix of the stored hash.
	 */
	private const PREFIX = 'lwfw_pkb_';

	/**
	 * Constructor.
	 *
	 * @param \Closure|null $writer Receives ( value, options ) instead of setcookie() (tests).
	 */
	public function __construct( private readonly ?\Closure $writer = null ) {}

	/**
	 * Bind a fresh challenge to this browser.
	 *
	 * @param string $key Challenge key.
	 */
	public function issue( string $key ): void {
		if ( ! self::valid( $key ) ) {
			return;
		}

		$value = bin2hex( random_bytes( 16 ) );
		set_transient( self::PREFIX . $key, hash( 'sha256', $value ), self::TTL );
		$this->write( $value, time() + self::TTL );
	}

	/**
	 * Whether this browser holds the cookie of this challenge (spends it).
	 *
	 * @param string $key Challenge key from the request.
	 */
	public function check( string $key ): bool {
		$cookie = self::cookie();
		if ( '' !== $cookie ) {
			$this->write( '', time() - 3600 );
		}
		if ( ! self::valid( $key ) ) {
			return false;
		}

		$stored = get_transient( self::PREFIX . $key );
		delete_transient( self::PREFIX . $key );

		return is_string( $stored ) && '' !== $cookie && hash_equals( $stored, hash( 'sha256', $cookie ) );
	}

	/**
	 * The binding cookie of the request ('' = none or malformed).
	 */
	private static function cookie(): string {
		$raw = isset( $_COOKIE[ self::COOKIE ] ) && is_string( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';

		return 1 === preg_match( '/^[0-9a-f]{32}$/D', $raw ) ? $raw : '';
	}

	/**
	 * Challenge keys are 32 lowercase hex characters (ChallengeStore::put()).
	 *
	 * @param string $key Key.
	 */
	private static function valid( string $key ): bool {
		return 1 === preg_match( '/^[0-9a-f]{32}$/D', $key );
	}

	/**
	 * Set or clear the cookie.
	 *
	 * @param string $value   Value ('' clears).
	 * @param int    $expires Expiry timestamp.
	 */
	private function write( string $value, int $expires ): void {
		$options = array(
			'expires'  => $expires,
			'path'     => defined( 'COOKIEPATH' ) && '' !== (string) COOKIEPATH ? (string) COOKIEPATH : '/',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Strict',
		);
		if ( null !== $this->writer ) {
			( $this->writer )( $value, $options );
			return;
		}
		if ( ! headers_sent() ) {
			setcookie( self::COOKIE, $value, $options );
		}
	}
}
