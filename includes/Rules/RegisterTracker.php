<?php
/**
 * Rejected-registration tracking (spam auto-ban).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\Logger;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Counts rejected registration attempts per IP and bans the IP once the
 * configured threshold is reached within the ban-duration window. The ban is
 * written to the shared firewall ban store (via AutoBanner) so the MU-plugin
 * worker blocks every subsequent request from that IP before WordPress loads.
 */
final class RegisterTracker {

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
	 * Hook-friendly entry point: skip whitelisted IPs, resolve storage and
	 * record the rejection.
	 *
	 * @return void
	 */
	public static function record_reject(): void {
		$ip        = IpDetector::get_ip();
		$whitelist = (array) Options::get( 'ip_whitelist', [] );

		if ( ! empty( $whitelist ) && IpMatcher::matches( $ip, $whitelist ) ) {
			return;
		}

		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		( new self( $storage ) )->record();
	}

	/**
	 * Record a rejected registration for the current IP and ban it once the
	 * threshold is reached.
	 *
	 * @return void
	 */
	public function record(): void {
		$ip        = IpDetector::get_ip();
		$threshold = (int) Options::get( 'register_ban_threshold', 3 );
		$duration  = (int) Options::get( 'register_ban_duration', 3600 );

		$count = $this->storage->increment( 'register_reject_' . $ip, $duration );

		if ( $count < $threshold ) {
			return;
		}

		( new AutoBanner( $this->storage ) )->ban( $ip, $duration );

		if ( ! empty( Options::get( 'log_enabled' ) ) ) {
			Logger::log(
				[
					'ip'     => $ip,
					'reason' => 'register_spam',
					'ua'     => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 ),
					'url'    => sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ),
				]
			);
		}
	}
}
