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
			$this->storage->set( 'ban_' . $ip, 1, $duration );
		}
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
