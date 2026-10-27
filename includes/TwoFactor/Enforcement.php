<?php
/**
 * Role-based two-factor requirement with a grace period.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\Options;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A user is required when one of their roles on the current site is in
 * `twofa_required_roles` (on multisite a super admin also counts when
 * 'administrator' is listed, because super admins often hold no role on the
 * site). Nothing is required while `twofa_enabled` is off.
 *
 * The grace clock (UserFactors::META_SINCE) starts on the first evaluation of
 * a required user and is written once; a user who becomes required later
 * (role change) starts the grace then. A factor reset keeps it (see
 * UserFactors::reset_all()), so it never opens a fresh password-only window.
 *
 * Enforcement never locks anyone out: after the grace a password login is
 * held for enrollment (LoginInterceptor + EnrollmentController) instead.
 */
final class Enforcement {

	/**
	 * Upper bound of the grace period in days (OptionSchema range).
	 */
	private const MAX_GRACE_DAYS = 90;

	/**
	 * Constructor.
	 *
	 * @param \Closure|null $clock Returns the current Unix time (tests); null = time().
	 */
	public function __construct( private readonly ?\Closure $clock = null ) {}

	/**
	 * Whether the user's roles on this site make a second factor mandatory.
	 *
	 * @param WP_User $user User.
	 */
	public function is_required( WP_User $user ): bool {
		if ( (int) $user->ID <= 0 || ! (bool) Options::get( 'twofa_enabled', false ) ) {
			return false;
		}

		$required = self::required_roles();
		if ( array() === $required ) {
			return false;
		}

		if ( array() !== array_intersect( array_map( 'strval', (array) $user->roles ), $required ) ) {
			return true;
		}

		return in_array( 'administrator', $required, true ) && is_multisite() && is_super_admin( (int) $user->ID );
	}

	/**
	 * When the user's grace period ends (Unix time); starts the clock on first use.
	 *
	 * @param WP_User $user User.
	 */
	public function grace_ends_at( WP_User $user ): int {
		return $this->since( (int) $user->ID ) + self::grace_days() * DAY_IN_SECONDS;
	}

	/**
	 * Whether the next password login must set up a second factor first.
	 *
	 * @param WP_User $user User.
	 */
	public function must_enroll_now( WP_User $user ): bool {
		if ( ! $this->is_required( $user ) ) {
			return false;
		}

		// Evaluated before has_any(), so the clock also runs for users with
		// factors: a later reset must not get a fresh grace window.
		$ends = $this->grace_ends_at( $user );

		return ! ( new UserFactors( (int) $user->ID ) )->has_any() && $this->now() >= $ends;
	}

	/**
	 * Whether the user is required, has no factor yet and is still inside the grace.
	 *
	 * @param WP_User $user User.
	 */
	public function in_grace( WP_User $user ): bool {
		if ( ! $this->is_required( $user ) ) {
			return false;
		}

		$ends = $this->grace_ends_at( $user );

		return ! ( new UserFactors( (int) $user->ID ) )->has_any() && $this->now() < $ends;
	}

	/**
	 * Whole days left of the grace, rounded up (0 = over).
	 *
	 * @param WP_User $user User.
	 */
	public function days_left( WP_User $user ): int {
		$left = $this->grace_ends_at( $user ) - $this->now();

		return $left > 0 ? (int) ceil( $left / DAY_IN_SECONDS ) : 0;
	}

	/**
	 * Configured grace length in days, clamped to 0–90.
	 */
	public static function grace_days(): int {
		return min( self::MAX_GRACE_DAYS, max( 0, (int) Options::get( 'twofa_grace_days', 7 ) ) );
	}

	/**
	 * Roles that must use a second factor.
	 *
	 * @return string[]
	 */
	private static function required_roles(): array {
		$roles = Options::get( 'twofa_required_roles', array() );

		return is_array( $roles ) ? array_values( array_filter( array_map( 'strval', $roles ), static fn ( string $role ): bool => '' !== $role ) ) : array();
	}

	/**
	 * Start of the grace clock, written once when missing.
	 *
	 * @param int $user_id User.
	 */
	private function since( int $user_id ): int {
		$factors = new UserFactors( $user_id );
		$since   = $factors->grace_since();
		if ( $since > 0 ) {
			return $since;
		}

		$now = $this->now();
		$factors->start_grace( $now );

		return $now;
	}

	/**
	 * Current Unix time.
	 */
	private function now(): int {
		return null === $this->clock ? time() : (int) ( $this->clock )();
	}
}
