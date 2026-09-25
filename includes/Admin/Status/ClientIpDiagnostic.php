<?php
/**
 * How the firewall sees the current request's client address.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Status;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\ProxyTrust;
use LightweightPlugins\Firewall\Rules\CountGuard;
use LightweightPlugins\Firewall\Rules\IpMatcher;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The detected client IP next to its raw ingredients (REMOTE_ADDR, the
 * forwarded headers present, whether REMOTE_ADDR is a trusted proxy or
 * Cloudflare), so an operator can verify proxy resolution (issue #6).
 *
 * It describes the admin's own request: an admin browsing from a LAN or VPN
 * sees a private address here even when visitors resolve correctly.
 */
final class ClientIpDiagnostic {

	/**
	 * Forwarding headers worth showing: $_SERVER key => header name.
	 */
	private const HEADERS = [
		'HTTP_CF_CONNECTING_IP' => 'CF-Connecting-IP',
		'HTTP_X_FORWARDED_FOR'  => 'X-Forwarded-For',
		'HTTP_X_REAL_IP'        => 'X-Real-IP',
		'HTTP_FORWARDED'        => 'Forwarded',
		'HTTP_TRUE_CLIENT_IP'   => 'True-Client-IP',
		'HTTP_X_CLIENT_IP'      => 'X-Client-IP',
	];

	/**
	 * Longest header value echoed back.
	 */
	private const MAX_VALUE = 300;

	/**
	 * Build the diagnostic for the current request.
	 *
	 * @return array<string, mixed>
	 */
	public static function build(): array {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Validated by filter_var.
		$raw_remote = trim( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ) );
		$remote     = false !== filter_var( $raw_remote, FILTER_VALIDATE_IP ) ? $raw_remote : '';
		$proxies    = array_map( 'strval', (array) Options::get( 'trusted_proxies', [] ) );
		$header     = (string) Options::get( 'proxy_header', 'x-forwarded-for' );
		$cloudflare = IpDetector::is_cloudflare_request( $remote );
		$configured = ProxyTrust::is_configured( $proxies );
		$trusted    = $configured && '' !== $remote && IpMatcher::matches( $remote, $proxies );
		$forwarded  = $cloudflare ? '' : ProxyTrust::resolve( $remote, $proxies, $header );
		$detected   = IpDetector::get_ip();

		return [
			'detected_ip'         => $detected,
			'remote_addr'         => $remote,
			'source'              => self::source( $cloudflare, $forwarded ),
			'cloudflare'          => $cloudflare,
			'proxies_configured'  => $configured,
			'trusted_proxy_match' => $trusted,
			'proxy_header'        => $header,
			'forwarded_headers'   => self::headers( $_SERVER ),
			'routable'            => ! ProxyTrust::is_non_routable( $detected ),
			'counted'             => CountGuard::allows_for( $detected, $proxies ),
		];
	}

	/**
	 * Where the detected address came from.
	 *
	 * @param bool   $cloudflare Whether the request came through Cloudflare.
	 * @param string $forwarded  Address resolved from a trusted proxy header.
	 * @return string cloudflare | trusted_proxy | remote_addr.
	 */
	public static function source( bool $cloudflare, string $forwarded ): string {
		if ( $cloudflare ) {
			return 'cloudflare';
		}

		return '' !== $forwarded ? 'trusted_proxy' : 'remote_addr';
	}

	/**
	 * The forwarding headers present on the request, name and value.
	 *
	 * The values are client-controlled: control characters are stripped and
	 * the length is capped. They are data for display, never trusted.
	 *
	 * @param array<string, mixed> $server Request server variables.
	 * @return array<int, array{name: string, value: string}>
	 */
	public static function headers( array $server ): array {
		$present = [];

		foreach ( self::HEADERS as $key => $name ) {
			if ( ! isset( $server[ $key ] ) || ! is_scalar( $server[ $key ] ) || '' === trim( (string) $server[ $key ] ) ) {
				continue;
			}

			$value     = (string) preg_replace( '/[\x00-\x1F\x7F]+/', '', (string) $server[ $key ] );
			$present[] = [
				'name'  => $name,
				'value' => substr( trim( $value ), 0, self::MAX_VALUE ),
			];
		}

		return $present;
	}
}
