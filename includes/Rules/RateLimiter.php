<?php
/**
 * IP-based rate limiting.
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
 * Limits the number of filter requests per IP within a time window.
 */
final class RateLimiter {

	/**
	 * Storage backend for counters.
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
	 * Check if the IP is within the rate limit.
	 *
	 * Returns true if allowed, false if rate limit exceeded.
	 *
	 * @param string $ip Client IP address.
	 * @return bool
	 */
	public function is_allowed( string $ip ): bool {
		$limit  = (int) Options::get( 'rate_limit', 30 );
		$window = (int) Options::get( 'rate_window', 60 );

		$key   = 'rl_' . $ip;
		$count = $this->storage->increment( $key, $window );

		return $count <= $limit;
	}

	/**
	 * Perform the rate limit action (redirect or 429).
	 */
	public static function limit(): void {
		$action = Options::get( 'action', 'redirect' );

		if ( 'redirect' === $action ) {
			self::redirect();
		} else {
			self::too_many_requests();
		}
	}

	/**
	 * 302 redirect to the shop base URL (strips filter params).
	 */
	private static function redirect(): void {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Used for redirect target, path only.
		$path = strtok( $_SERVER['REQUEST_URI'] ?? '/', '?' );

		if ( ! headers_sent() ) {
			header( 'HTTP/1.1 302 Found' );
			header( 'Location: ' . $path );
			header( 'Cache-Control: no-store, no-cache' );
		}

		exit;
	}

	/**
	 * Send a 429 Too Many Requests response.
	 */
	private static function too_many_requests(): void {
		$window = (int) Options::get( 'rate_window', 60 );

		if ( ! headers_sent() ) {
			header( 'HTTP/1.1 429 Too Many Requests' );
			header( 'Retry-After: ' . $window );
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'Cache-Control: no-store, no-cache' );
		}

		echo 'Too many requests. Please try again later.';
		exit;
	}
}
