<?php
/**
 * LW Firewall — Uninstall
 *
 * Cleans up options and removes the MU-plugin worker.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Remove plugin options.
delete_option( 'lw_firewall' );
delete_option( 'lw_firewall_log' );

// Remove MU-plugin worker.
$lw_firewall_worker = WPMU_PLUGIN_DIR . '/lw-firewall-worker.php';
if ( file_exists( $lw_firewall_worker ) ) {
	wp_delete_file( $lw_firewall_worker );
}

// Remove file storage cache directory.
$lw_firewall_cache_dir = WP_CONTENT_DIR . '/cache/lw-firewall/';
if ( is_dir( $lw_firewall_cache_dir ) ) {
	$lw_firewall_files = glob( $lw_firewall_cache_dir . '*' );
	if ( is_array( $lw_firewall_files ) ) {
		foreach ( $lw_firewall_files as $lw_firewall_file ) {
			if ( is_file( $lw_firewall_file ) ) {
				wp_delete_file( $lw_firewall_file );
			}
		}
	}
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
	rmdir( $lw_firewall_cache_dir );
}
