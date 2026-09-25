<?php
/**
 * Shapes the ban index for the admin API.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Bans;

use LightweightPlugins\Firewall\IpSubject;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns BanList::all() rows into labelled list items plus a summary.
 */
final class BanRows {

	/**
	 * Bans expiring within this many seconds count as "expiring soon".
	 */
	private const SOON = 3600;

	/**
	 * Build the items and the summary.
	 *
	 * @param array<int, array{ip: string, expires: int, reason: string, time: int, active: bool}> $rows Reconciled ban rows.
	 * @param int                                                                                  $now  Current UNIX timestamp.
	 * @return array{items: array<int, array<string, mixed>>, summary: array{total: int, enforced: int, tracked_only: int, expiring_soon: int}}
	 */
	public static function build( array $rows, int $now ): array {
		$items = [];
		$live  = 0;
		$soon  = 0;

		foreach ( $rows as $row ) {
			$items[] = self::item( $row );

			if ( $row['active'] ) {
				++$live;
				$soon += ( $row['expires'] - $now ) < self::SOON ? 1 : 0;
			}
		}

		return [
			'items'   => $items,
			'summary' => [
				'total'         => count( $rows ),
				'enforced'      => $live,
				'tracked_only'  => count( $rows ) - $live,
				'expiring_soon' => $soon,
			],
		];
	}

	/**
	 * One list item.
	 *
	 * @param array{ip: string, expires: int, reason: string, time: int, active: bool} $row Ban row.
	 * @return array<string, mixed>
	 */
	private static function item( array $row ): array {
		return [
			'ip'           => $row['ip'],
			'kind'         => self::kind( $row['ip'] ),
			'reason'       => $row['reason'],
			'reason_label' => BanReasons::label( $row['reason'] ),
			'reason_hint'  => BanReasons::hint( $row['reason'] ),
			'source'       => BanReasons::source( $row['reason'] ),
			'time'         => $row['time'],
			'expires'      => $row['expires'],
			'active'       => $row['active'],
		];
	}

	/**
	 * What an index key stands for.
	 *
	 * @param string $ip Index key.
	 * @return string `network` (an IPv6 /64), `legacy` (a per-address IPv6
	 *                ban from 1.5.8 or earlier) or `ip`.
	 */
	public static function kind( string $ip ): string {
		if ( IpSubject::is_subject_key( $ip ) ) {
			return 'network';
		}

		return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 'legacy' : 'ip';
	}
}
