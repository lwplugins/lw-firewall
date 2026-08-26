<?php
/**
 * Password-reset request rate limiting.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Counts password-reset requests along three independent axes, because a
 * reset flood does not have one shape:
 *
 * - per IP     — one host hammering the lost-password form;
 * - per target — many hosts requesting resets for the *same* account, which
 *                floods that person's inbox. Per-IP limiting cannot see this
 *                at all, and it is the shape used to harass a specific user
 *                or to bury a real reset email under noise;
 * - site-wide  — the total number of reset emails the site will send in an
 *                hour, which protects the hosting mail quota and stops the
 *                sending domain from being flagged as a spam source.
 *
 * The target counter is keyed by user ID, not by the submitted string, so
 * "admin", "Admin" and the account's email address all land in one bucket.
 *
 * Cheaper checks run first and short-circuit: once the IP is over its limit
 * the request is refused without touching the target counter, so an attacker
 * cannot use their own flood to lock the victim out of a genuine reset.
 */
final class ResetLimiter {

	/**
	 * Verdicts returned by record().
	 */
	public const ALLOW  = '';
	public const IP     = 'ip';
	public const GLOBAL = 'global';
	public const USER   = 'user';

	/**
	 * Storage backend.
	 *
	 * @var StorageInterface
	 */
	private StorageInterface $storage;

	/**
	 * Limit configuration.
	 *
	 * @var array<string, int>
	 */
	private array $limits;

	/**
	 * Constructor.
	 *
	 * @param StorageInterface   $storage Storage backend.
	 * @param array<string, int> $limits  Keys: ip_max, ip_window, user_max,
	 *                                    user_window, global_max, global_window.
	 *                                    A max of 0 disables that axis.
	 */
	public function __construct( StorageInterface $storage, array $limits ) {
		$this->storage = $storage;
		$this->limits  = $limits;
	}

	/**
	 * Record one reset request and decide whether it may proceed.
	 *
	 * @param string $ip      Requesting IP.
	 * @param int    $user_id Target account, or 0 when the account is unknown
	 *                        or the request already looks like bot traffic.
	 * @return string One of the verdict constants; ALLOW ('') means proceed.
	 */
	public function record( string $ip, int $user_id ): string {
		if ( '' !== $ip && $this->over( 'reset_ip_' . $ip, 'ip_max', 'ip_window' ) ) {
			return self::IP;
		}

		if ( $this->over( 'reset_all', 'global_max', 'global_window' ) ) {
			return self::GLOBAL;
		}

		if ( $user_id > 0 && $this->over( 'reset_user_' . $user_id, 'user_max', 'user_window' ) ) {
			return self::USER;
		}

		return self::ALLOW;
	}

	/**
	 * Increment one counter and report whether it is now over its limit.
	 *
	 * @param string $key        Storage key.
	 * @param string $max_key    Limit config key holding the allowance.
	 * @param string $window_key Limit config key holding the window in seconds.
	 * @return bool
	 */
	private function over( string $key, string $max_key, string $window_key ): bool {
		$max = (int) ( $this->limits[ $max_key ] ?? 0 );

		if ( $max <= 0 ) {
			return false;
		}

		$window = max( 1, (int) ( $this->limits[ $window_key ] ?? 3600 ) );

		return $this->storage->increment( $key, $window ) > $max;
	}
}
