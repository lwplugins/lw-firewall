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
	 * Seconds an IP/reason pair stays collapsed into one entry.
	 */
	private const DEDUPE_WINDOW = 300;

	/**
	 * Log a blocked request.
	 *
	 * @param array<string, mixed> $entry Log data with ip, reason, ua, url keys.
	 */
	public static function log( array $entry ): void {
		if ( ! Options::get( 'log_enabled' ) ) {
			return;
		}

		// Under a flood every blocked request wrote the whole option back:
		// a get_option, a full array rebuild and an update_option per attacker
		// hit, turning the defence into a database amplifier. The same IP and
		// reason now collapse into one entry with a counter for the window.
		if ( self::is_duplicate( $entry ) ) {
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
	 * Whether this IP/reason pair was already logged inside the window.
	 *
	 * The marker lives in the firewall's own storage backend, which is memory
	 * on any real install — so the check that prevents a database write does
	 * not itself cost one.
	 *
	 * @param array<string, mixed> $entry Log data.
	 * @return bool
	 */
	private static function is_duplicate( array $entry ): bool {
		$ip     = (string) ( $entry['ip'] ?? '' );
		$reason = (string) ( $entry['reason'] ?? '' );

		if ( '' === $ip && '' === $reason ) {
			return false;
		}

		if ( ! function_exists( 'lw_firewall_resolve_storage' ) ) {
			return false;
		}

		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );

		return $storage->increment( 'log_seen_' . md5( IpSubject::of( $ip ) . '|' . $reason ), self::DEDUPE_WINDOW ) > 1;
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
