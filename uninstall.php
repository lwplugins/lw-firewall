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

// Remove log data only — keep settings for reinstall.
delete_option( 'lw_firewall_log' );

// Remove the known-administrator snapshot used by the new-admin alert.
delete_option( 'lw_firewall_admin_baseline' );
delete_option( 'lw_firewall_bans' );
delete_option( 'lw_firewall_user_locks' );
delete_option( 'lw_firewall_alert_queue' );
delete_option( 'lw_firewall_dropped_filter_params' );
delete_transient( 'lw_firewall_admin_alert_mail_error' );
delete_option( 'lw_firewall_2fa_mail_failed' );

// Remove every two-factor user meta row: the factors, the passkey lookup and
// user handle, the remember salt, the grace start and the attempt counters
// (`_lw_firewall_2fa_tok_*`, `_lw_firewall_2fa_fail`, `_lw_firewall_2fa_bind`).
// The usermeta table is network-wide, so one pass covers every site.
global $wpdb;
$lw_firewall_2fa_keys = [
	'_lw_firewall_totp',
	'_lw_firewall_recovery',
	'_lw_firewall_passkeys',
	'_lw_firewall_passkey_lookup',
	'_lw_firewall_user_handle',
	'_lw_firewall_remember_salt',
];
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off uninstall cleanup across all users.
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->usermeta} WHERE meta_key IN (" . implode( ', ', array_fill( 0, count( $lw_firewall_2fa_keys ), '%s' ) ) . ') OR meta_key LIKE %s', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Core table name; one %s placeholder per key.
		...array_merge( $lw_firewall_2fa_keys, [ $wpdb->esc_like( '_lw_firewall_2fa_' ) . '%' ] )
	)
);
if ( function_exists( 'wp_cache_flush_group' ) ) {
	wp_cache_flush_group( 'user_meta' );
}

// Remove the administrator scan cron event.
$lw_firewall_scan_event = wp_next_scheduled( 'lw_firewall_admin_scan' );
if ( $lw_firewall_scan_event ) {
	wp_unschedule_event( $lw_firewall_scan_event, 'lw_firewall_admin_scan' );
}

// Remove MU-plugin worker.
$lw_firewall_worker = WPMU_PLUGIN_DIR . '/lw-firewall-worker.php';
if ( file_exists( $lw_firewall_worker ) ) {
	wp_delete_file( $lw_firewall_worker );
}

// Remove the file storage cache directory, including the geo sub-directory —
// a flat glob left it behind, so rmdir() failed and the whole tree survived.
$lw_firewall_cache_dir = WP_CONTENT_DIR . '/cache/lw-firewall/';

/**
 * Delete a directory and everything under it.
 *
 * @param string $dir Absolute path.
 * @return void
 */
function lw_firewall_remove_tree( string $dir ): void {
	$entries = glob( rtrim( $dir, '/' ) . '/*' );

	if ( is_array( $entries ) ) {
		foreach ( $entries as $entry ) {
			if ( is_dir( $entry ) ) {
				lw_firewall_remove_tree( $entry );
				continue;
			}

			wp_delete_file( $entry );
		}
	}

	if ( is_dir( $dir ) ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir, WordPress.PHP.NoSilencedErrors.Discouraged -- A non-empty or unwritable directory is not worth failing an uninstall over.
		@rmdir( $dir );
	}
}

if ( is_dir( $lw_firewall_cache_dir ) ) {
	lw_firewall_remove_tree( $lw_firewall_cache_dir );
}

// Remove every schedule the plugin owns.
foreach ( [ 'lw_firewall_admin_scan', 'lw_firewall_geo_update' ] as $lw_firewall_hook ) {
	wp_clear_scheduled_hook( $lw_firewall_hook );
}
