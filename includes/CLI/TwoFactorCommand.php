<?php
/**
 * Two-factor CLI command.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\CLI;

use LightweightPlugins\Firewall\TwoFactor\Summary;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;
use WP_CLI;
use WP_CLI\Utils;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two-factor adoption and the lost-device reset.
 */
final class TwoFactorCommand {

	/**
	 * Show the second factors of a user, or the adoption per role.
	 *
	 * Prints counts only, never a secret or a code.
	 *
	 * ## OPTIONS
	 *
	 * [<user>]
	 * : User login, email or ID. Without it: users with a second factor per role.
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall 2fa status
	 *     $ wp lw-firewall 2fa status alice
	 *
	 * @param array<int, string>   $args       Positional arguments.
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 */
	public function status( array $args, array $assoc_args ): void {
		$format = (string) Utils\get_flag_value( $assoc_args, 'format', 'table' );

		if ( isset( $args[0] ) ) {
			$this->user_status( self::resolve( $args[0] ), $format );
			return;
		}

		$summary = Summary::build();
		$rows    = array();

		foreach ( $summary['roles'] as $role ) {
			$rows[] = array(
				'role'     => $role['role'],
				'users'    => $role['users'],
				'with_2fa' => $role['with_2fa'],
				'required' => $role['required'] ? 'yes' : 'no',
			);
		}

		Utils\format_items( $format, $rows, array( 'role', 'users', 'with_2fa', 'required' ) );
		WP_CLI::log( sprintf( 'Total: %d of %d users have a second factor%s.', $summary['total_with_2fa'], $summary['total_users'], $summary['truncated'] ? ' (at least; large site, count capped)' : '' ) );
	}

	/**
	 * Remove every second factor of a user (lost device).
	 *
	 * Deletes the authenticator, the recovery codes and the passkeys, and
	 * forgets every remembered device. The user can enroll again at next login.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User login, email or ID.
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     $ wp lw-firewall 2fa reset alice --yes
	 *
	 * @param array<int, string>   $args       Positional arguments.
	 * @param array<string, mixed> $assoc_args Associative arguments.
	 */
	public function reset( array $args, array $assoc_args ): void {
		$user = self::resolve( $args[0] ?? '' );

		WP_CLI::confirm( sprintf( "Remove every second factor of '%s' (#%d)?", $user->user_login, $user->ID ), $assoc_args );

		( new UserFactors( (int) $user->ID ) )->reset_all();

		WP_CLI::success( sprintf( "Two-factor reset for '%s'.", $user->user_login ) );
	}

	/**
	 * Print which factors one user has.
	 *
	 * @param WP_User $user   User.
	 * @param string  $format Output format.
	 */
	private function user_status( WP_User $user, string $format ): void {
		$factors = new UserFactors( (int) $user->ID );
		$totp    = $factors->has_totp() ? 'yes' : ( $factors->has_totp_record() ? 'unreadable' : 'no' );

		Utils\format_items(
			$format,
			array(
				array(
					'user'           => $user->user_login,
					'totp'           => $totp,
					'recovery_codes' => count( $factors->recovery_hashes() ),
					'passkeys'       => count( $factors->passkeys() ),
				),
			),
			array( 'user', 'totp', 'recovery_codes', 'passkeys' )
		);
	}

	/**
	 * Resolve a login, email or ID to a user, or stop with an error.
	 *
	 * @param string $identifier Login, email or numeric ID.
	 * @return WP_User
	 */
	private static function resolve( string $identifier ): WP_User {
		$user = false;

		if ( ctype_digit( $identifier ) ) {
			$user = get_user_by( 'id', (int) $identifier );
		}
		if ( ! $user && str_contains( $identifier, '@' ) ) {
			$user = get_user_by( 'email', $identifier );
		}
		if ( ! $user ) {
			$user = get_user_by( 'login', $identifier );
		}
		if ( ! $user instanceof WP_User ) {
			WP_CLI::error( sprintf( "User '%s' not found.", $identifier ) );
		}

		return $user;
	}
}
