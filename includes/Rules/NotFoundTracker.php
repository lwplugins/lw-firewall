<?php
/**
 * 404 flood tracking.
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
 * Tracks 404 responses per IP and blocks flooding.
 */
final class NotFoundTracker {

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
	 * Record a 404 hit for the current IP. Called from template_redirect.
	 */
	public function record(): void {
		$ip     = IpDetector::get_ip();
		$window = (int) Options::get( 'rate_window', 60 );
		$limit  = (int) Options::get( 'rate_limit', 30 );
		$count  = $this->storage->increment( '404_' . $ip, $window );

		// Log only the request that first crosses the threshold. A 404 flood
		// never escalates to a ban here, so `$count > $limit` would write a log
		// line for every request past the limit — turning the logger into an
		// unbounded write amplifier during the very flood it is meant to record.
		if ( $count === $limit + 1 && ! empty( Options::get( 'log_enabled' ) ) ) {
			Logger::log(
				[
					'ip'     => $ip,
					'reason' => 'rate_limited_404',
					'ua'     => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 ),
					'url'    => sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ),
				]
			);
		}
	}

	/**
	 * Check if an IP has exceeded the 404 flood limit.
	 *
	 * @param string $ip Client IP.
	 * @return bool True if the IP should be blocked.
	 */
	public function is_flooding( string $ip ): bool {
		$limit = (int) Options::get( 'rate_limit', 30 );
		$count = $this->storage->get( '404_' . $ip );

		return null !== $count && (int) $count > $limit;
	}
}
