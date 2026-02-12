<?php
/**
 * Storage backend detector.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Detects which storage backend is active based on preference.
 */
final class StorageDetector {

	/**
	 * Detect the active storage backend name.
	 *
	 * @param string $preference User preference: 'auto', 'apcu', 'redis', 'file'.
	 * @return string Human-readable storage name.
	 */
	public static function detect( string $preference ): string {
		if ( 'apcu' === $preference && ApcuStorage::is_available() ) {
			return 'APCu';
		}
		if ( 'redis' === $preference && RedisStorage::is_available() ) {
			return 'Redis';
		}
		if ( 'file' === $preference ) {
			return 'File';
		}

		// Auto-detect.
		if ( ApcuStorage::is_available() ) {
			return 'APCu (auto)';
		}
		if ( RedisStorage::is_available() ) {
			return 'Redis (auto)';
		}
		return 'File (auto)';
	}
}
