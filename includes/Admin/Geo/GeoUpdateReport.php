<?php
/**
 * Per-country result of a CIDR list update.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Geo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns CidrUpdater::update_country_report() into a row the admin shows.
 */
final class GeoUpdateReport {

	/**
	 * One country's row.
	 *
	 * @param string                                   $cc     Country code.
	 * @param array{v4: bool, v6: bool, written: bool} $report Updater report.
	 * @return array{cc: string, v4: bool, v6: bool, message: string}
	 */
	public static function row( string $cc, array $report ): array {
		if ( $report['v4'] && $report['v6'] ) {
			$message = __( 'IPv4 and IPv6 lists updated.', 'lw-firewall' );
		} elseif ( $report['v4'] ) {
			$message = __( 'IPv4 list updated; the IPv6 list could not be downloaded.', 'lw-firewall' );
		} elseif ( $report['v6'] ) {
			$message = __( 'IPv6 list updated; the IPv4 list could not be downloaded.', 'lw-firewall' );
		} elseif ( $report['written'] ) {
			$message = __( 'The cache was written but holds no list.', 'lw-firewall' );
		} else {
			$message = __( 'Update failed: the lists could not be downloaded, or the cache directory is not writable.', 'lw-firewall' );
		}

		return [
			'cc'      => $cc,
			'v4'      => $report['v4'],
			'v6'      => $report['v6'],
			'message' => $message,
		];
	}
}
