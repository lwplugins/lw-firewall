<?php
/**
 * Administrator account detection.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Answers "who is an administrator right now, and what do they look like?"
 * straight from the database.
 *
 * Deliberately role-based (plus multisite super admins) rather than
 * capability-based: `user_can()` runs through dynamic capability filters, so a
 * plugin that grants caps per request would make the baseline flap and emit
 * false alerts. Role membership is stable, cheap to enumerate, and is what an
 * attacker actually writes when escalating through the database.
 */
final class AdminDetector {

	/**
	 * The WordPress administrator role slug.
	 */
	public const ADMIN_ROLE = 'administrator';

	/**
	 * Identity fields compared between snapshots.
	 *
	 * @var array<int, string>
	 */
	public const PROFILE_FIELDS = [ 'login', 'email', 'pass' ];

	/**
	 * Every current administrator, keyed by user ID, with their identity
	 * fingerprint.
	 *
	 * @return array<int, array<string, string>>
	 */
	public static function current_admins(): array {
		$users = get_users(
			[
				'role'   => self::ADMIN_ROLE,
				'number' => -1,
			]
		);

		$admins = [];

		foreach ( (array) $users as $user ) {
			if ( $user instanceof WP_User ) {
				$admins[ (int) $user->ID ] = self::fingerprint( $user );
			}
		}

		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$user = get_user_by( 'login', (string) $login );

				if ( $user instanceof WP_User ) {
					$admins[ (int) $user->ID ] = self::fingerprint( $user );
				}
			}
		}

		ksort( $admins );

		return $admins;
	}

	/**
	 * All user IDs that currently hold administrator privileges.
	 *
	 * @return array<int, int> Sorted, unique user IDs.
	 */
	public static function current_admin_ids(): array {
		return self::normalize( array_keys( self::current_admins() ) );
	}

	/**
	 * The identity fingerprint of a single user.
	 *
	 * @param int $user_id User ID.
	 * @return array<string, string>|null Null when the user does not exist.
	 */
	public static function profile( int $user_id ): ?array {
		$user = get_userdata( $user_id );

		return $user instanceof WP_User ? self::fingerprint( $user ) : null;
	}

	/**
	 * Whether a single user currently holds administrator privileges.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_admin_user( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		$user = get_userdata( $user_id );

		if ( ! $user instanceof WP_User ) {
			return false;
		}

		if ( in_array( self::ADMIN_ROLE, (array) $user->roles, true ) ) {
			return true;
		}

		return is_multisite() && is_super_admin( $user_id );
	}

	/**
	 * Human-readable facts about a user, for the alert email body.
	 *
	 * @param int $user_id User ID.
	 * @return array<string, string> Label => value pairs.
	 */
	public static function describe( int $user_id ): array {
		$user = get_userdata( $user_id );

		if ( ! $user instanceof WP_User ) {
			return [
				__( 'User ID', 'lw-firewall' ) => (string) $user_id,
				__( 'Status', 'lw-firewall' )  => __( 'account no longer exists', 'lw-firewall' ),
			];
		}

		$roles = (array) $user->roles;

		$details = [
			__( 'Username', 'lw-firewall' )     => (string) $user->user_login,
			__( 'Email', 'lw-firewall' )        => (string) $user->user_email,
			__( 'Display name', 'lw-firewall' ) => (string) $user->display_name,
			__( 'User ID', 'lw-firewall' )      => (string) $user->ID,
			__( 'Roles', 'lw-firewall' )        => $roles ? implode( ', ', array_map( 'strval', $roles ) ) : __( '(none)', 'lw-firewall' ),
			__( 'Registered', 'lw-firewall' )   => (string) $user->user_registered,
		];

		if ( is_multisite() && is_super_admin( $user_id ) ) {
			$details[ __( 'Super admin', 'lw-firewall' ) ] = __( 'yes', 'lw-firewall' );
		}

		$details[ __( 'Profile', 'lw-firewall' ) ] = admin_url( 'user-edit.php?user_id=' . $user_id );

		return $details;
	}

	/**
	 * Reduce a raw ID list to sorted, unique, positive integers.
	 *
	 * Pure — no WordPress calls — so the baseline diff stays testable.
	 *
	 * @param array<int|string, mixed> $ids Raw IDs.
	 * @return array<int, int>
	 */
	public static function normalize( array $ids ): array {
		$clean = [];

		foreach ( $ids as $id ) {
			$id = (int) $id;

			if ( $id > 0 ) {
				$clean[] = $id;
			}
		}

		$clean = array_values( array_unique( $clean ) );
		sort( $clean );

		return $clean;
	}

	/**
	 * Build the identity fingerprint stored in the baseline.
	 *
	 * The username and email are kept verbatim so an alert can name what
	 * changed. The password is stored only as a digest of the stored hash —
	 * enough to notice a change, useless to anyone who reads the option.
	 *
	 * @param WP_User $user User object.
	 * @return array<string, string>
	 */
	private static function fingerprint( WP_User $user ): array {
		return [
			'login' => (string) $user->user_login,
			'email' => (string) $user->user_email,
			'pass'  => hash( 'sha256', (string) $user->user_pass ),
		];
	}
}
