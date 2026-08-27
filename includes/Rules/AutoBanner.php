<?php
/**
 * Auto-ban logic for repeat offenders.
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
 * Escalating ban: after N rate-limit violations an IP is banned for a longer period.
 */
final class AutoBanner {

	/**
	 * Storage backend.
	 *
	 * @var StorageInterface
	 */
	private StorageInterface $storage;

	/**
	 * Constructor.
	 *
	 * @param StorageInterface $storage Storage backend.
	 */
	public function __construct( StorageInterface $storage ) {
		$this->storage = $storage;
	}

	/**
	 * Check if an IP is currently auto-banned.
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	public function is_banned( string $ip ): bool {
		return (bool) $this->storage->get( 'ban_' . $ip );
	}

	/**
	 * Record a rate-limit violation and auto-ban if threshold reached.
	 *
	 * @param string $ip Client IP.
	 */
	public function record_violation( string $ip ): void {
		$threshold = (int) Options::get( 'auto_ban_threshold', 3 );
		$duration  = (int) Options::get( 'auto_ban_duration', 3600 );

		$key   = 'violations_' . $ip;
		$count = $this->storage->increment( $key, $duration );

		if ( $count >= $threshold ) {
			$this->ban( $ip, $duration, 'rate_limit' );
		}
	}

	/**
	 * Ban an IP for a given duration by writing the shared ban key.
	 *
	 * The reason is recorded in the listable index only; enforcement reads the
	 * storage key alone, so nothing on the hot path depends on it.
	 *
	 * @param string $ip       Client IP.
	 * @param int    $duration Ban length in seconds.
	 * @param string $reason   Short machine-readable reason code.
	 */
	public function ban( string $ip, int $duration, string $reason = '' ): void {
		$this->storage->set( 'ban_' . $ip, 1, $duration );

		BanList::record( $ip, $duration, $reason );
	}

	/**
	 * Lift a ban and clear the counters that produced it.
	 *
	 * Deleting only the ban key is not enough: the violation counters outlive
	 * it, so the very next request from that IP would find the count already
	 * past the threshold and ban it again. Everything that can re-trigger a
	 * ban for this address is cleared in one go — this is what makes "unblock
	 * me" actually work when a user reports being locked out.
	 *
	 * @param string $ip Client IP.
	 * @return bool Whether the address is unbanned afterwards.
	 */
	public function unban( string $ip ): bool {
		if ( '' === $ip ) {
			return false;
		}

		$this->storage->delete( 'ban_' . $ip );

		foreach ( self::counter_keys( $ip ) as $key ) {
			$this->storage->delete( $key );
		}

		BanList::forget( $ip );

		return ! $this->is_banned( $ip );
	}

	/**
	 * Every counter whose threshold can produce a ban for this IP.
	 *
	 * @param string $ip Client IP.
	 * @return array<int, string>
	 */
	private static function counter_keys( string $ip ): array {
		return [
			'violations_' . $ip,      // Rate-limit escalation.
			'login_fail_' . $ip,      // Brute-force login lockout.
			'register_reject_' . $ip, // Registration spam.
			'reset_ip_' . $ip,        // Password-reset flood.
			'404_' . $ip,             // 404 flood.
			'rl_' . $ip,              // Global per-IP rate-limit counter.
		];
	}

	/**
	 * Send a 403 Forbidden response for banned IPs.
	 */
	public static function block(): void {
		if ( ! headers_sent() ) {
			header( 'HTTP/1.1 403 Forbidden' );
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'Cache-Control: no-store, no-cache' );
		}

		echo 'Access denied. Your IP has been temporarily banned.';
		exit;
	}
}
