<?php
/**
 * Rejected-registration tracking (spam auto-ban).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\IpSubject;
use LightweightPlugins\Firewall\Logger;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Counts rejected spam submissions (registrations, comments and product
 * reviews) per IP and bans the IP once the configured threshold is reached
 * within the ban-duration window. Every spam form shares one counter and one
 * threshold: a bot hitting the comment form and the registration form is one
 * offender, not two half-offenders. The ban is
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
	 * @param string $reason Ban reason code recorded when the threshold is hit.
	 * @return void
	 */
	public static function record_reject( string $reason = 'register_spam' ): void {
		$ip        = IpDetector::get_ip();
		$whitelist = (array) Options::get( 'ip_whitelist', [] );

		if ( ! empty( $whitelist ) && IpMatcher::matches( $ip, $whitelist ) ) {
			return;
		}

		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		( new self( $storage ) )->record( $reason );
	}

	/**
	 * Record a rejected spam submission for the current IP and ban it once the
	 * threshold is reached.
	 *
	 * @param string $reason Ban reason code recorded when the threshold is hit.
	 * @return void
	 */
	public function record( string $reason = 'register_spam' ): void {
		$ip = IpDetector::get_ip();

		if ( ! CountGuard::allows( $ip ) ) {
			return;
		}

		$threshold = (int) Options::get( 'register_ban_threshold', 3 );
		$duration  = (int) Options::get( 'register_ban_duration', 3600 );

		$count = $this->storage->increment( 'register_reject_' . IpSubject::of( $ip ), $duration );

		if ( $count < $threshold ) {
			return;
		}

		( new AutoBanner( $this->storage ) )->ban( $ip, $duration, $reason );

		if ( ! empty( Options::get( 'log_enabled' ) ) ) {
			Logger::log(
				[
					'ip'     => $ip,
					'reason' => $reason,
					'ua'     => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 ),
					'url'    => sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ),
				]
			);
		}
	}
}
