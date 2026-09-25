<?php
/**
 * Per-username failed-login lockout.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Counts failed logins per username — whoever sends them — and locks that
 * username for everyone once the limit is reached within the login detection
 * window. A distributed brute force rotates IPs, so the per-IP ban alone never
 * trips; the account it targets does not change.
 *
 * It is a real lockout: while locked, the username cannot log in even with
 * the right password, until the lock expires or an administrator lifts it.
 * Unknown usernames are counted too (otherwise the lock would tell an
 * attacker which accounts exist); the counters are TTL'd storage keys and the
 * listable index is capped.
 */
final class UserLockout {

	/**
	 * Storage key prefix of a lock.
	 */
	public const LOCK_PREFIX = 'user_lock_';

	/**
	 * Storage key prefix of a failure counter.
	 */
	public const COUNT_PREFIX = 'login_user_fail_';

	/**
	 * Constructor.
	 *
	 * @param StorageInterface $storage Storage backend.
	 */
	public function __construct( private StorageInterface $storage ) {
	}

	/**
	 * Whether a login is locked right now.
	 *
	 * @param string $login Username (already resolved from an email if needed).
	 * @return bool
	 */
	public function is_locked( string $login ): bool {
		$key = UsernameKey::hash( $login );

		return '' !== $key && (bool) $this->storage->get( self::LOCK_PREFIX . $key );
	}

	/**
	 * Count one failed login; lock the username when the limit is reached.
	 *
	 * An attempt against an already locked username is not counted, so the
	 * lock is not extended by the very requests it refuses.
	 *
	 * @param string $login Username (already resolved from an email if needed).
	 * @return bool Whether this failure locked the username.
	 */
	public function record_failure( string $login ): bool {
		$key = UsernameKey::hash( $login );

		if ( '' === $key || $this->is_locked( $login ) ) {
			return false;
		}

		$limit    = (int) Options::get( 'login_user_max_attempts', 10 );
		$window   = (int) Options::get( 'login_lockout_window', 600 );
		$duration = (int) Options::get( 'login_user_lockout_duration', 900 );

		if ( $this->storage->increment( self::COUNT_PREFIX . $key, $window ) < $limit ) {
			return false;
		}

		$this->storage->set( self::LOCK_PREFIX . $key, 1, max( 60, $duration ) );
		$this->storage->delete( self::COUNT_PREFIX . $key );
		UserLockList::record( $key, $login, $duration );

		return true;
	}

	/**
	 * Lift a lock and clear its counter.
	 *
	 * @param string $key UsernameKey::hash() of the login.
	 * @return bool Whether the username is unlocked afterwards.
	 */
	public function unlock( string $key ): bool {
		if ( ! UsernameKey::is_hash( $key ) ) {
			return false;
		}

		$this->storage->delete( self::LOCK_PREFIX . $key );
		$this->storage->delete( self::COUNT_PREFIX . $key );

		if ( $this->storage->get( self::LOCK_PREFIX . $key ) ) {
			return false;
		}

		UserLockList::forget( $key );

		return true;
	}
}
