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
	 * Key prefix for the backends that share memory between sites.
	 *
	 * A fixed prefix meant two WordPress installations on one APCu pool or Redis
	 * database collided: the same visitor shared a rate-limit counter, a ban and
	 * a single-use token across unrelated sites. Derived from the install path,
	 * so it is stable for a site and distinct between sites.
	 *
	 * @return string
	 */
	public static function key_prefix(): string {
		$seed = defined( 'ABSPATH' ) ? (string) ABSPATH : __DIR__;

		return 'lw_fw_' . substr( md5( $seed ), 0, 8 ) . '_';
	}

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
