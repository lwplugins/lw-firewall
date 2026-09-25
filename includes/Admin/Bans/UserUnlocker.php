<?php
/**
 * Lifts username locks and reports each outcome.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Bans;

use LightweightPlugins\Firewall\Rules\LoginResolver;
use LightweightPlugins\Firewall\Rules\UserLockList;
use LightweightPlugins\Firewall\Rules\UserLockout;
use LightweightPlugins\Firewall\Rules\UsernameKey;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Per-username unlock results, like Unbanner does for addresses.
 */
final class UserUnlocker {

	/**
	 * Constructor.
	 *
	 * @param UserLockout $lockout Lockout bound to the active storage.
	 */
	public function __construct( private UserLockout $lockout ) {
	}

	/**
	 * Unlock the given lock keys (or usernames, which are hashed).
	 *
	 * @param array<int, mixed> $targets Lock keys from the listing, or usernames.
	 * @return array<int, array{key: string, user: string, ok: bool, message: string}>
	 */
	public function unlock( array $targets ): array {
		$names   = UserLockList::names();
		$results = [];

		foreach ( $targets as $target ) {
			// The same resolver as the lockout: an email or a Unicode variant
			// unlocks the account it logs into.
			$target = is_scalar( $target ) ? trim( (string) $target ) : '';
			$key    = UsernameKey::is_hash( $target ) ? $target : UsernameKey::hash( LoginResolver::resolve( $target ) );
			$user   = $names[ $key ] ?? $target;

			if ( '' === $key ) {
				$results[] = self::result( $key, $user, false, __( 'That is not a username.', 'lw-firewall' ) );
				continue;
			}

			if ( ! isset( $names[ $key ] ) && ! $this->lockout->is_key_locked( $key ) ) {
				$results[] = self::result( $key, $user, false, __( 'This username is not locked.', 'lw-firewall' ) );
				continue;
			}

			$results[] = $this->lockout->unlock( $key )
				? self::result( $key, $user, true, __( 'Username unlocked. Its failed-login count was cleared too.', 'lw-firewall' ) )
				: self::result( $key, $user, false, __( 'The lock could not be lifted — the storage backend refused the delete.', 'lw-firewall' ) );
		}

		return $results;
	}

	/**
	 * Unlock every tracked username.
	 *
	 * @return array<int, array{key: string, user: string, ok: bool, message: string}>
	 */
	public function unlock_all(): array {
		return $this->unlock( UserLockList::keys() );
	}

	/**
	 * One result row.
	 *
	 * @param string $key     Lock key.
	 * @param string $user    Username for display.
	 * @param bool   $ok      Whether it is unlocked now.
	 * @param string $message Human-readable outcome.
	 * @return array{key: string, user: string, ok: bool, message: string}
	 */
	private static function result( string $key, string $user, bool $ok, string $message ): array {
		return [
			'key'     => $key,
			'user'    => $user,
			'ok'      => $ok,
			'message' => $message,
		];
	}
}
