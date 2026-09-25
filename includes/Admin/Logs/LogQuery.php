<?php
/**
 * Filters and pages the request log.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Logs;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Server-side reason filter, search and pagination over the (at most 100)
 * stored entries, newest first.
 */
final class LogQuery {

	/**
	 * Largest page size accepted.
	 */
	public const MAX_PER_PAGE = 100;

	/**
	 * Run the query.
	 *
	 * @param array<int, mixed> $entries  Stored log entries.
	 * @param int               $page     1-based page.
	 * @param int               $per_page Page size.
	 * @param string            $reason   Base reason code to keep ('' for all).
	 * @param string            $search   Case-insensitive substring of IP, user agent or URL.
	 * @return array{items: array<int, array<string, string>>, total: int, page: int, per_page: int, pages: int, reasons: array<string, string>}
	 */
	public static function run( array $entries, int $page, int $per_page, string $reason, string $search ): array {
		$rows     = array_values( array_filter( array_map( [ self::class, 'row' ], $entries ) ) );
		$reasons  = self::reasons( $rows );
		$rows     = array_values( array_filter( $rows, static fn ( array $row ): bool => self::matches( $row, $reason, $search ) ) );
		$per_page = max( 1, min( self::MAX_PER_PAGE, $per_page ) );
		$pages    = max( 1, (int) ceil( count( $rows ) / $per_page ) );
		$page     = max( 1, min( $pages, $page ) );

		return [
			'items'    => array_slice( $rows, ( $page - 1 ) * $per_page, $per_page ),
			'total'    => count( $rows ),
			'page'     => $page,
			'per_page' => $per_page,
			'pages'    => $pages,
			'reasons'  => $reasons,
		];
	}

	/**
	 * One normalised row, or null for a malformed entry.
	 *
	 * @param mixed $entry Stored entry.
	 * @return array<string, string>|null
	 */
	private static function row( mixed $entry ): ?array {
		if ( ! is_array( $entry ) ) {
			return null;
		}

		$reason = (string) ( $entry['reason'] ?? '' );

		return [
			'time'         => (string) ( $entry['time'] ?? '' ),
			'ip'           => (string) ( $entry['ip'] ?? '' ),
			'reason'       => $reason,
			'reason_code'  => LogReasons::code( $reason ),
			'reason_label' => LogReasons::label( $reason ),
			'ua'           => (string) ( $entry['ua'] ?? '' ),
			'url'          => (string) ( $entry['url'] ?? '' ),
		];
	}

	/**
	 * Reason codes present in the log => label, for the filter.
	 *
	 * @param array<int, array<string, string>> $rows Normalised rows.
	 * @return array<string, string>
	 */
	private static function reasons( array $rows ): array {
		$reasons = [];

		foreach ( $rows as $row ) {
			$reasons[ $row['reason_code'] ] = LogReasons::label( $row['reason_code'] );
		}

		ksort( $reasons );

		return $reasons;
	}

	/**
	 * Whether a row passes the filter and the search.
	 *
	 * @param array<string, string> $row    Normalised row.
	 * @param string                $reason Base reason code, or ''.
	 * @param string                $search Search term, or ''.
	 * @return bool
	 */
	private static function matches( array $row, string $reason, string $search ): bool {
		if ( '' !== $reason && $row['reason_code'] !== $reason ) {
			return false;
		}

		if ( '' === $search ) {
			return true;
		}

		$haystack = strtolower( $row['ip'] . "\n" . $row['ua'] . "\n" . $row['url'] );

		return str_contains( $haystack, strtolower( $search ) );
	}
}
