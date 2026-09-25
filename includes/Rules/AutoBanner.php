<?php
/**
 * Auto-ban logic for repeat offenders.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\IpSubject;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Escalating ban: after N rate-limit violations an IP is banned for a longer period.
 *
 * Bans and counters are keyed by the client's subject (see IpSubject): the
 * address itself for IPv4, the whole /64 for IPv6.
 */
final class AutoBanner {

	/**
	 * Shortest ban the storage will be asked for, in seconds.
	 */
	public const MIN_DURATION = 60;

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
	 * Check if an IP (or the /64 it belongs to) is currently banned.
	 *
	 * 1.5.8 and earlier keyed IPv6 bans by the full address. Those keys are
	 * still honoured until they expire, so an upgrade never silently releases
	 * an address that was banned before it.
	 *
	 * @param string $ip Client IP, or a subject key.
	 * @return bool
	 */
	public function is_banned( string $ip ): bool {
		$subject = IpSubject::of( $ip );

		if ( $this->storage->get( 'ban_' . $subject ) ) {
			return true;
		}

		return $subject !== $ip && (bool) $this->storage->get( 'ban_' . $ip );
	}

	/**
	 * Record a rate-limit violation and auto-ban if threshold reached.
	 *
	 * @param string $ip Client IP.
	 */
	public function record_violation( string $ip ): void {
		$threshold = (int) Options::get( 'auto_ban_threshold', 3 );
		$duration  = (int) Options::get( 'auto_ban_duration', 3600 );

		$key   = 'violations_' . IpSubject::of( $ip );
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
		// A zero duration meant "no TTL" to every backend, i.e. a permanent ban
		// that nothing would ever lift on its own. A ban is a temporary measure;
		// the blacklist is where permanent belongs.
		$duration = max( self::MIN_DURATION, $duration );

		$subject = IpSubject::of( $ip );

		$this->storage->set( 'ban_' . $subject, 1, $duration );

		BanList::record( $subject, $duration, $reason );
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
	 * Any address inside a banned /64, or the /64 key itself, lifts the ban.
	 * Per-address keys written by 1.5.8 inside the same /64 are cleared too.
	 *
	 * @param string $target Client IP or IPv6 /64 subject key.
	 * @return bool Whether the address is unbanned afterwards.
	 */
	public function unban( string $target ): bool {
		$subject = IpSubject::parse( $target );

		if ( '' === $subject ) {
			return false;
		}

		$identities = self::identities( trim( $target ), $subject );

		foreach ( $identities as $identity ) {
			$this->storage->delete( 'ban_' . $identity );

			foreach ( self::counter_keys( $identity ) as $key ) {
				$this->storage->delete( $key );
			}

			BanList::forget( $identity );
		}

		foreach ( $identities as $identity ) {
			if ( $this->storage->get( 'ban_' . $identity ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Every storage identity an unban has to clear: the subject, plus any
	 * legacy per-address identity inside it (the target itself, and indexed
	 * 1.5.8 bans that belong to the same /64).
	 *
	 * @param string $target  Operator input, trimmed.
	 * @param string $subject Its subject key.
	 * @return array<int, string>
	 */
	private static function identities( string $target, string $subject ): array {
		$identities = [ $subject ];

		if ( filter_var( $target, FILTER_VALIDATE_IP ) ) {
			$identities[] = $target;
		}

		foreach ( BanList::ips() as $indexed ) {
			if ( IpSubject::of( $indexed ) === $subject ) {
				$identities[] = $indexed;
			}
		}

		return array_values( array_unique( $identities ) );
	}

	/**
	 * Every counter whose threshold can produce a ban for this IP.
	 *
	 * @param string $ip Client IP.
	 * @return array<int, string>
	 */
	private static function counter_keys( string $ip ): array {
		$keys = [
			'violations_' . $ip,      // Rate-limit escalation.
			'login_fail_' . $ip,      // Brute-force login lockout.
			'register_reject_' . $ip, // Registration spam.
			'reset_ip_' . $ip,        // Password-reset flood.
			'404_' . $ip,             // 404 flood.
			'rl_' . $ip,              // Global per-IP rate-limit counter.
		];

		// The worker counts each endpoint in its own bucket, and signed-in
		// requests in a second one. Leaving these behind meant an address could
		// be unbanned and still be refused until the rate window aged out —
		// while the admin screen reported it released.
		foreach ( [ 'cron', 'xmlrpc', 'login', 'rest', 'filter' ] as $endpoint ) {
			$keys[] = $endpoint . '_' . $ip;
			$keys[] = $endpoint . '_li_' . $ip;
		}

		return $keys;
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
