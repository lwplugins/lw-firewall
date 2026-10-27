<?php
/**
 * Per-role two-factor adoption summary.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\TwoFactor\Passkey\WebAuthnFactory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * How many users of each role enrolled a second factor.
 *
 * One bounded query finds the users holding a factor meta row; the totals
 * come from count_users(). Counts only: no secret, hash or user identity.
 */
final class Summary {

	/**
	 * Most factor holders inspected; beyond it the counts are a lower bound.
	 */
	public const LIMIT = 5000;

	/**
	 * Build the summary.
	 *
	 * @return array{roles: array<int, array{role: string, label: string, users: int, with_2fa: int, required: bool}>, total_users: int, total_with_2fa: int, truncated: bool, passkeys_available: bool, crypto_available: bool}
	 */
	public static function build(): array {
		$holders = self::holders();
		$with    = array();
		$total   = 0;

		foreach ( $holders as $user ) {
			if ( ! ( new UserFactors( (int) $user->ID ) )->has_any() ) {
				continue;
			}
			++$total;
			foreach ( (array) $user->roles as $role ) {
				$with[ (string) $role ] = ( $with[ (string) $role ] ?? 0 ) + 1;
			}
		}

		$counts   = count_users();
		$required = self::required_roles();
		$avail    = $counts['avail_roles'];
		$roles    = array();

		foreach ( wp_roles()->get_names() as $slug => $name ) {
			$roles[] = array(
				'role'     => (string) $slug,
				'label'    => translate_user_role( (string) $name ),
				'users'    => (int) ( $avail[ $slug ] ?? 0 ),
				'with_2fa' => $with[ $slug ] ?? 0,
				'required' => in_array( (string) $slug, $required, true ),
			);
		}

		return array(
			'roles'              => $roles,
			'total_users'        => $counts['total_users'],
			'total_with_2fa'     => $total,
			'truncated'          => count( $holders ) >= self::LIMIT,
			'passkeys_available' => WebAuthnFactory::available(),
			'crypto_available'   => TwoFactorModule::crypto_available(),
		);
	}

	/**
	 * Users holding a TOTP or passkey meta row (a row can still be an emptied list).
	 *
	 * @return \WP_User[]
	 */
	private static function holders(): array {
		return get_users(
			array(
				'meta_query' => array( // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query -- One bounded admin-only lookup.
					'relation' => 'OR',
					array(
						'key'     => UserFactors::META_TOTP,
						'compare' => 'EXISTS',
					),
					array(
						'key'     => UserFactors::META_PASSKEYS,
						'compare' => 'EXISTS',
					),
				),
				'number'     => self::LIMIT,
				'orderby'    => 'ID',
				'fields'     => 'all',
			)
		);
	}

	/**
	 * Roles that must use a second factor.
	 *
	 * @return string[]
	 */
	private static function required_roles(): array {
		$roles = Options::get( 'twofa_required_roles', array() );

		return is_array( $roles ) ? array_values( array_map( 'strval', $roles ) ) : array();
	}
}
