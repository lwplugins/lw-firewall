<?php
/**
 * Failed-login tracking (brute-force / fail2ban style).
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
 * Counts failed login attempts per IP and bans the IP once the configured
 * threshold is reached within the lockout window.
 *
 * The ban is written to the shared firewall ban store (via AutoBanner) so the
 * MU-plugin worker blocks every subsequent request from that IP before
 * WordPress loads. The failure counter ages out naturally after the lockout
 * window — there is no reset-on-success, matching fail2ban findtime semantics.
 */
final class LoginTracker {

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
	 * Hook entry point for wp_login_failed: skip whitelisted IPs, resolve the
	 * configured storage backend and record the failure.
	 *
	 * @return void
	 */
	public static function handle(): void {
		$ip        = IpDetector::get_ip();
		$whitelist = (array) Options::get( 'ip_whitelist', [] );

		if ( ! empty( $whitelist ) && IpMatcher::matches( $ip, $whitelist ) ) {
			return;
		}

		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		( new self( $storage ) )->record_failure();
	}

	/**
	 * Record a failed login for the current IP and ban it once the threshold
	 * is reached.
	 *
	 * @return void
	 */
	public function record_failure(): void {
		$ip        = IpDetector::get_ip();
		$threshold = (int) Options::get( 'login_max_attempts', 5 );
		$window    = (int) Options::get( 'login_lockout_window', 600 );
		$duration  = (int) Options::get( 'login_lockout_duration', 3600 );

		$count = $this->storage->increment( 'login_fail_' . $ip, $window );

		if ( $count < $threshold ) {
			return;
		}

		( new AutoBanner( $this->storage ) )->ban( $ip, $duration );

		if ( ! empty( Options::get( 'log_enabled' ) ) ) {
			Logger::log(
				[
					'ip'     => $ip,
					'reason' => 'login_lockout',
					'ua'     => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 ),
					'url'    => sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ),
				]
			);
		}
	}
}
