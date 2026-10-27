<?php
/**
 * "Remember this device": a signed cookie that skips the second factor for a while.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Cookie value: `user_id|issued|expires|hmac`, hmac = HMAC-SHA256 of `user_id|issued|expires`
 * keyed with wp_salt('auth') plus the user's remember salt. Resetting the
 * user's factors rotates that salt (as does a factor or password change, see
 * RememberRevoker), which kills every remembered device. The issue time is
 * signed so that lowering the admin's lifetime also shortens old cookies.
 */
final class RememberDevice {

	/**
	 * Cookie name prefix (COOKIEHASH is appended).
	 */
	private const PREFIX = 'lwfw_2fa_rd_';

	/**
	 * Clock.
	 *
	 * @var \Closure
	 */
	private \Closure $clock;

	/**
	 * Cookie writer ( name, value, options ); null = setcookie().
	 *
	 * @var \Closure|null
	 */
	private ?\Closure $writer;

	/**
	 * Constructor.
	 *
	 * @param \Closure|null $clock  Returns the current time; null = time().
	 * @param \Closure|null $writer Sets the cookie; null = setcookie().
	 */
	public function __construct( ?\Closure $clock = null, ?\Closure $writer = null ) {
		$this->clock  = $clock ?? static fn (): int => time();
		$this->writer = $writer;
	}

	/**
	 * Configured lifetime in days (0 = the feature is off).
	 */
	public static function days(): int {
		return max( 0, (int) Options::get( 'twofa_remember_days' ) );
	}

	/**
	 * Cookie name.
	 */
	public static function cookie_name(): string {
		return self::PREFIX . ( defined( 'COOKIEHASH' ) ? COOKIEHASH : '' );
	}

	/**
	 * Remember this browser for a user.
	 *
	 * @param int $user_id User ID.
	 * @param int $days    Lifetime in days.
	 */
	public function issue( int $user_id, int $days ): void {
		if ( $user_id <= 0 || $days <= 0 ) {
			return;
		}

		$issued  = ( $this->clock )();
		$expires = $issued + $days * DAY_IN_SECONDS;
		$value   = $user_id . '|' . $issued . '|' . $expires . '|' . $this->sign( $user_id, $issued, $expires );
		$options = array(
			'expires'  => $expires,
			'path'     => defined( 'COOKIEPATH' ) && '' !== COOKIEPATH ? COOKIEPATH : '/',
			'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		);

		if ( null !== $this->writer ) {
			( $this->writer )( self::cookie_name(), $value, $options );
			return;
		}

		setcookie( self::cookie_name(), $value, $options );
		$_COOKIE[ self::cookie_name() ] = $value;
	}

	/**
	 * Whether this browser carries a valid, unexpired cookie for the user.
	 *
	 * Ignored while the admin has the feature off (days = 0).
	 *
	 * @param int $user_id User ID.
	 */
	public function is_valid( int $user_id ): bool {
		if ( $user_id <= 0 || self::days() <= 0 ) {
			return false;
		}

		$raw = wp_unslash( $_COOKIE[ self::cookie_name() ] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Strictly parsed and HMAC-checked below.
		if ( ! is_string( $raw ) ) {
			return false;
		}

		$parts = explode( '|', $raw );
		if ( 4 !== count( $parts ) || ! ctype_digit( $parts[0] ) || ! ctype_digit( $parts[1] ) || ! ctype_digit( $parts[2] ) ) {
			return false;
		}

		$issued  = (int) $parts[1];
		$expires = (int) $parts[2];
		$now     = ( $this->clock )();
		if ( (int) $parts[0] !== $user_id || $expires <= $now || $issued > $now || $issued + self::days() * DAY_IN_SECONDS <= $now ) {
			return false;
		}

		return hash_equals( $this->sign( $user_id, $issued, $expires ), $parts[3] );
	}

	/**
	 * The signature of a cookie payload.
	 *
	 * @param int $user_id User ID.
	 * @param int $issued  Issue timestamp.
	 * @param int $expires Expiry timestamp.
	 */
	private function sign( int $user_id, int $issued, int $expires ): string {
		$salt = ( new UserFactors( $user_id ) )->remember_salt();

		return hash_hmac( 'sha256', $user_id . '|' . $issued . '|' . $expires, wp_salt( 'auth' ) . $salt );
	}
}
