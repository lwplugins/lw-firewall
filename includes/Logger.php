<?php
/**
 * Request logging.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stores and retrieves blocked request log entries in the database.
 */
final class Logger {

	private const LOG_OPTION  = 'lw_firewall_log';
	private const MAX_ENTRIES = 100;

	/**
	 * Log a blocked request.
	 *
	 * @param array<string, mixed> $entry Log data with ip, reason, ua, url keys.
	 */
	public static function log( array $entry ): void {
		if ( ! Options::get( 'log_enabled' ) ) {
			return;
		}

		$entry['time'] = current_time( 'mysql' );

		$log = get_option( self::LOG_OPTION, [] );

		if ( ! is_array( $log ) ) {
			$log = [];
		}

		// Prepend latest entry.
		array_unshift( $log, $entry );

		// Keep only the last N entries.
		$log = array_slice( $log, 0, self::MAX_ENTRIES );

		update_option( self::LOG_OPTION, $log, false );
	}

	/**
	 * Get all log entries.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_entries(): array {
		$log = get_option( self::LOG_OPTION, [] );

		return is_array( $log ) ? $log : [];
	}

	/**
	 * Clear all log entries.
	 */
	public static function clear(): void {
		delete_option( self::LOG_OPTION );
	}
}
