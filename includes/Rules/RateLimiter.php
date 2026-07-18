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
	 * @param string $ip Client IP address.
	 * @return bool
	 */
	public function is_allowed( string $ip ): bool {
		return $this->is_allowed_key( 'rl_' . $ip );
	}

	/**
	 * Check if a given counter key is within the rate limit.
	 *
	 * @param string   $key   Counter key.
	 * @param int|null $limit Optional custom rate limit (overrides global setting).
	 * @return bool
	 */
	public function is_allowed_key( string $key, ?int $limit = null ): bool {
		$limit  = $limit ?? (int) Options::get( 'rate_limit', 30 );
		$window = (int) Options::get( 'rate_window', 60 );
		$count  = $this->storage->increment( $key, $window );

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
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Path only, sanitized in safe_redirect_path().
		$path = self::safe_redirect_path( (string) ( $_SERVER['REQUEST_URI'] ?? '/' ) );

		if ( ! headers_sent() ) {
			header( 'HTTP/1.1 302 Found' );
			header( 'Location: ' . $path );
			header( 'Cache-Control: no-store, no-cache' );
		}

		exit;
	}

	/**
	 * Reduce a request URI to a single-slash-rooted local path.
	 *
	 * Strips the query string and collapses leading slashes so a crafted request
	 * line like "GET //evil.example/" cannot turn into a protocol-relative (open)
	 * redirect via the Location header.
	 *
	 * @param string $request_uri Raw REQUEST_URI.
	 * @return string
	 */
	public static function safe_redirect_path( string $request_uri ): string {
		$path = strtok( $request_uri, '?' );

		return '/' . ltrim( (string) $path, '/' );
	}

	/**
	 * Send a 429 Too Many Requests response (public alias).
	 */
	public static function too_many(): void {
		self::too_many_requests();
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
