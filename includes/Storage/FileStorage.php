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
		}

		CacheDirectory::protect( $this->dir );
		CacheDirectory::sweep( $this->dir );
	}

	/**
	 * Read a file under a shared lock.
	 *
	 * Writers truncate before they rewrite, so an unlocked read can see an
	 * empty or half-written file.
	 *
	 * @param string $file Absolute path.
	 * @return string|null Raw contents, or null when unreadable.
	 */
	private function read_locked( string $file ): ?string {
		if ( ! file_exists( $file ) ) {
			return null;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.PHP.NoSilencedErrors.Discouraged -- A vanished or unreadable cache file is an expected race, not an error to surface.
		$handle = @fopen( $file, 'rb' );

		if ( false === $handle ) {
			return null;
		}

		try {
			if ( ! flock( $handle, LOCK_SH ) ) {
				return null;
			}

			$size = (int) filesize( $file );

			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
			$data = $size > 0 ? fread( $handle, $size ) : '';

			return false === $data ? null : $data;
		} finally {
			flock( $handle, LOCK_UN );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			fclose( $handle );
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

		$data = $this->read_locked( $file );

		if ( null === $data ) {
			return null;
		}

		// allowed_classes: this file only ever holds scalars, and refusing object
		// instantiation removes the gadget surface entirely.
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize
		$entry = @unserialize( $data, [ 'allowed_classes' => false ] );

		// A partial read is not a corrupt entry. Deleting here removed live
		// keys — a ban or a flood counter — precisely under the concurrency the
		// firewall exists to handle, because a writer truncates before it
		// rewrites. Report "no value" and let the next write settle it.
		if ( ! is_array( $entry ) || ! isset( $entry['expires'], $entry['value'] ) ) {
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
		$file = $this->get_file_path( $key );

		// Atomic read-modify-write under an exclusive lock. A plain get()+set()
		// lets two concurrent requests both read the same counter and each
		// overwrite the other's increment, so a burst of N parallel requests
		// raises the counter by far less than N — letting a flood past the
		// limit exactly under the load rate limiting exists to stop.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		$handle = @fopen( $file, 'c+' );

		if ( false === $handle ) {
			// Best-effort fallback if the file can't be opened.
			$current = $this->get( $key );
			$new     = is_int( $current ) ? $current + 1 : 1;
			$this->set( $key, $new, $ttl );
			return $new;
		}

		try {
			if ( ! flock( $handle, LOCK_EX ) ) {
				$current = $this->get( $key );
				$new     = is_int( $current ) ? $current + 1 : 1;
				$this->set( $key, $new, $ttl );
				return $new;
			}

			$raw   = stream_get_contents( $handle );
			$entry = ( is_string( $raw ) && '' !== $raw )
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize
				? @unserialize( $raw, [ 'allowed_classes' => false ] )
				: false;

			$now     = time();
			$expired = ! is_array( $entry )
				|| ! isset( $entry['expires'], $entry['value'] )
				|| ( $entry['expires'] > 0 && $entry['expires'] < $now );

			$current = ( ! $expired && is_int( $entry['value'] ) ) ? $entry['value'] : 0;
			$new     = $current + 1;

			// Fixed window, matching Redis and APCu. Re-stamping the expiry on
			// every increment turned this backend into a sliding window: steady
			// low-rate traffic never reset, so the same counter banned on file
			// storage and never banned on the others.
			$expires = $expired
				? ( $ttl > 0 ? $now + $ttl : 0 )
				: (int) $entry['expires'];

			$payload = serialize( // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
				[
					'expires' => $expires,
					'value'   => $new,
				]
			);

			rewind( $handle );
			ftruncate( $handle, 0 );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Locked counter file needs raw, atomic writes; WP_Filesystem is unsuitable here.
			fwrite( $handle, $payload );
			fflush( $handle );

			return $new;
		} finally {
			flock( $handle, LOCK_UN );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			fclose( $handle );
		}
	}

	/**
	 * Delete a key.
	 *
	 * @param string $key Cache key.
	 * @return bool
	 */
	public function delete( string $key ): bool {
		$file = $this->get_file_path( $key );

		if ( ! file_exists( $file ) ) {
			return true;
		}

		wp_delete_file( $file );

		// file_exists() is re-evaluated at runtime after the delete; PHPStan
		// cannot model wp_delete_file()'s filesystem side effect.
		// @phpstan-ignore booleanNot.alwaysFalse
		return ! file_exists( $file );
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
