<?php
/**
 * Shared helper functions used by both the main plugin and the MU-plugin worker.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolve the storage backend instance.
 *
 * @param string $preference Storage preference ('auto', 'apcu', 'redis', 'file').
 * @return LightweightPlugins\Firewall\Storage\StorageInterface
 */
function lw_firewall_resolve_storage( string $preference ): LightweightPlugins\Firewall\Storage\StorageInterface {
	if ( 'apcu' === $preference && LightweightPlugins\Firewall\Storage\ApcuStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\ApcuStorage();
	}

	if ( 'redis' === $preference && LightweightPlugins\Firewall\Storage\RedisStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\RedisStorage();
	}

	if ( 'file' === $preference ) {
		return new LightweightPlugins\Firewall\Storage\FileStorage();
	}

	// Auto-detect: apcu > redis > file.
	if ( LightweightPlugins\Firewall\Storage\ApcuStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\ApcuStorage();
	}

	if ( LightweightPlugins\Firewall\Storage\RedisStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\RedisStorage();
	}

	return new LightweightPlugins\Firewall\Storage\FileStorage();
}
