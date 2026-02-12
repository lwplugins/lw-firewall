<?php
/**
 * File-based storage backend.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rate-limit counter storage using filesystem cache files.
 * Fallback when APCu and Redis are not available.
 */
final class FileStorage implements StorageInterface {

	/**
	 * Cache directory path.
	 *
	 * @var string
	 */
	private string $dir;

	/**
	 * Initialize file storage and create cache directory if needed.
	 */
	public function __construct() {
		$upload_dir = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : dirname( __DIR__, 3 );
		$this->dir  = $upload_dir . '/cache/lw-firewall/';

		if ( ! is_dir( $this->dir ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
			@mkdir( $this->dir, 0755, true );

			// Prevent directory listing.
			$htaccess = $this->dir . '.htaccess';
			if ( ! file_exists( $htaccess ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				@file_put_contents( $htaccess, "Deny from all\n" );
			}
		}
	}

	/**
	 * Get a value by key.
	 *
	 * @param string $key Cache key.
	 * @return mixed
	 */
	public function get( string $key ): mixed {
		$file = $this->get_file_path( $key );

		if ( ! file_exists( $file ) ) {
			return null;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$data = @file_get_contents( $file );

		if ( false === $data ) {
			return null;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize
		$entry = @unserialize( $data );

		if ( ! is_array( $entry ) || ! isset( $entry['expires'], $entry['value'] ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			@unlink( $file );
			return null;
		}

		if ( $entry['expires'] > 0 && $entry['expires'] < time() ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			@unlink( $file );
			return null;
		}

		return $entry['value'];
	}

	/**
	 * Set a value with TTL in seconds.
	 *
	 * @param string $key   Cache key.
	 * @param mixed  $value Value to store.
	 * @param int    $ttl   Time-to-live in seconds.
	 * @return bool
	 */
	public function set( string $key, mixed $value, int $ttl ): bool {
		$file  = $this->get_file_path( $key );
		$entry = [
			'expires' => $ttl > 0 ? time() + $ttl : 0,
			'value'   => $value,
		];

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
		return (bool) @file_put_contents( $file, serialize( $entry ), LOCK_EX );
	}

	/**
	 * Increment a counter. Returns the new value.
	 *
	 * @param string $key Cache key.
	 * @param int    $ttl Time-to-live in seconds.
	 * @return int
	 */
	public function increment( string $key, int $ttl ): int {
		$current = $this->get( $key );
		$new     = is_int( $current ) ? $current + 1 : 1;

		$this->set( $key, $new, $ttl );

		return $new;
	}

	/**
	 * Check if file storage is available.
	 *
	 * @return bool
	 */
	public static function is_available(): bool {
		$dir = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : dirname( __DIR__, 3 );

		return is_writable( $dir );
	}

	/**
	 * Get file path for a cache key.
	 *
	 * @param string $key Cache key.
	 * @return string
	 */
	private function get_file_path( string $key ): string {
		return $this->dir . md5( $key ) . '.cache';
	}
}
