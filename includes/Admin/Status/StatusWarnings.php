<?php
/**
 * Warnings derived from the status report.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Status;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pure: turns the assembled status blocks into the list the admin shows at
 * the top of Status and counts in the navigation badge.
 */
final class StatusWarnings {

	/**
	 * Build the warnings.
	 *
	 * @param array<string, mixed> $status Status blocks: firewall, worker, storage, client_ip, geo, alerts.
	 * @return array<int, array{code: string, severity: string, message: string}>
	 */
	public static function from( array $status ): array {
		return array_merge(
			self::worker( $status['worker'], ! empty( $status['firewall']['enabled'] ) ),
			self::storage( $status['storage'] ),
			self::client_ip( $status['client_ip'] ),
			self::geo( $status['geo'], ! empty( $status['client_ip']['cloudflare'] ) ),
			self::alerts( $status['alerts'] )
		);
	}

	/**
	 * Worker and master switch warnings.
	 *
	 * @param array<string, mixed> $worker  Worker block.
	 * @param bool                 $enabled Firewall master switch.
	 * @return array<int, array{code: string, severity: string, message: string}>
	 */
	private static function worker( array $worker, bool $enabled ): array {
		$out = [];

		if ( ! empty( $worker['kill_switch'] ) ) {
			$out[] = self::item( 'worker_kill_switch', 'error', __( 'LW_FIREWALL_DISABLE_WORKER is set in wp-config.php, so the worker performs no checks at all.', 'lw-firewall' ) );
		}

		if ( ! $enabled ) {
			$out[] = self::item( 'firewall_disabled', 'warning', __( 'The firewall is switched off (General → Enable Firewall). No request is filtered.', 'lw-firewall' ) );
		}

		if ( empty( $worker['installed'] ) ) {
			$out[] = self::item( 'worker_missing', 'error', __( 'The MU-plugin worker is not installed, so runtime protection is off. Reinstall it below.', 'lw-firewall' ) );
		} elseif ( ! empty( $worker['outdated'] ) ) {
			$out[] = self::item( 'worker_outdated', 'error', __( 'The installed worker does not match this plugin version, so runtime protection is off until it is reinstalled.', 'lw-firewall' ) );
		} elseif ( 0 === (int) $worker['last_seen'] && empty( $worker['kill_switch'] ) ) {
			$out[] = self::item( 'worker_silent', 'warning', __( 'The worker file is installed but has never reported in. If this stays after a few page loads, the worker cannot load the plugin — most often because the plugin directory was renamed. Reinstall it below.', 'lw-firewall' ) );
		}

		$attempt = $worker['last_attempt'];

		if ( is_array( $attempt ) && empty( $attempt['success'] ) ) {
			/* translators: %s: reason the install failed */
			$out[] = self::item( 'worker_install_failed', 'error', sprintf( __( 'The last worker install attempt failed: %s', 'lw-firewall' ), $attempt['message'] ) );
		}

		if ( empty( $worker['mu_dir_writable'] ) ) {
			$out[] = self::item( 'mu_dir_not_writable', 'warning', __( 'The mu-plugins directory is not writable, so the worker cannot be installed or updated automatically.', 'lw-firewall' ) );
		}

		return $out;
	}

	/**
	 * Storage warnings.
	 *
	 * @param array<string, mixed> $storage Storage block.
	 * @return array<int, array{code: string, severity: string, message: string}>
	 */
	private static function storage( array $storage ): array {
		$out = [];

		if ( empty( $storage['probe']['ok'] ) ) {
			$out[] = self::item( 'storage_probe_failed', 'error', (string) $storage['probe']['message'] );
		}

		if ( 'file' === $storage['backend'] && empty( $storage['file_dir_writable'] ) ) {
			$out[] = self::item( 'file_cache_not_writable', 'error', __( 'The file storage directory is not writable, so rate limits, bans and counters cannot be stored.', 'lw-firewall' ) );
		}

		return $out;
	}

	/**
	 * Client address warnings.
	 *
	 * @param array<string, mixed> $ip Client IP block.
	 * @return array<int, array{code: string, severity: string, message: string}>
	 */
	private static function client_ip( array $ip ): array {
		$out = [];

		if ( empty( $ip['routable'] ) ) {
			$out[] = self::item(
				'ip_non_routable',
				'warning',
				sprintf(
					/* translators: %s: detected IP address */
					__( 'Your request reaches the firewall as %s, which is not routable on the internet. If visitors arrive the same way, they all share one rate-limit bucket, one ban and one country — list the proxy or load balancer under IP Rules → Reverse Proxy. If you are browsing from a LAN or VPN, only your own request may be affected.', 'lw-firewall' ),
					(string) $ip['detected_ip']
				)
			);
		}

		$headers = array_filter( (array) $ip['forwarded_headers'], static fn ( array $h ): bool => 'CF-Connecting-IP' !== $h['name'] );

		if ( [] !== $headers && empty( $ip['cloudflare'] ) && empty( $ip['trusted_proxy_match'] ) ) {
			$out[] = self::item(
				'proxy_headers_ignored',
				'info',
				sprintf(
					/* translators: 1: header names, 2: REMOTE_ADDR */
					__( 'The request carries %1$s, but REMOTE_ADDR %2$s is not a trusted proxy, so the header is ignored. If a proxy you control sets it, add %2$s under IP Rules → Trusted Proxies.', 'lw-firewall' ),
					implode( ', ', array_column( $headers, 'name' ) ),
					(string) $ip['remote_addr']
				)
			);
		}

		return $out;
	}

	/**
	 * Geo cache warnings. Behind Cloudflare the country header is used, so
	 * stale CIDR lists do not matter.
	 *
	 * @param array<string, mixed> $geo        Geo block.
	 * @param bool                 $cloudflare Whether the request came through Cloudflare.
	 * @return array<int, array{code: string, severity: string, message: string}>
	 */
	private static function geo( array $geo, bool $cloudflare ): array {
		$stale = array_column( array_filter( (array) $geo['countries'], static fn ( array $c ): bool => ! empty( $c['stale'] ) ), 'cc' );

		if ( empty( $geo['active'] ) || $cloudflare || [] === $stale ) {
			return [];
		}

		return [
			self::item(
				'geo_cache_stale',
				'warning',
				/* translators: %s: comma-separated country codes */
				sprintf( __( 'No current CIDR list for: %s. Geo blocking lets these visitors through until the lists are updated (Geo Blocking → Update CIDR lists).', 'lw-firewall' ), implode( ', ', $stale ) )
			),
		];
	}

	/**
	 * Administrator alert warnings.
	 *
	 * @param array<string, mixed> $alerts Alerts block.
	 * @return array<int, array{code: string, severity: string, message: string}>
	 */
	private static function alerts( array $alerts ): array {
		$out     = [];
		$pending = (int) $alerts['pending'];

		if ( $pending > 0 ) {
			/* translators: %d: number of alerts */
			$out[] = self::item( 'alerts_pending', 'warning', sprintf( _n( '%d alert could not be sent yet and will be retried on the next scan.', '%d alerts could not be sent yet and will be retried on the next scan.', $pending, 'lw-firewall' ), $pending ) );
		}

		if ( ! empty( $alerts['mail_error'] ) ) {
			$out[] = self::item( 'alerts_mail_error', 'warning', __( 'The last alert email could not be sent. Check your site mail configuration (SMTP plugin, hosting mail limits) — an alert that never arrives is no alert at all.', 'lw-firewall' ) );
		}

		return $out;
	}

	/**
	 * One warning.
	 *
	 * @param string $code     Stable machine code.
	 * @param string $severity error | warning | info.
	 * @param string $message  Human-readable text.
	 * @return array{code: string, severity: string, message: string}
	 */
	private static function item( string $code, string $severity, string $message ): array {
		return [
			'code'     => $code,
			'severity' => $severity,
			'message'  => $message,
		];
	}
}
