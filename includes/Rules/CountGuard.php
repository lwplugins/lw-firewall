<?php
/**
 * Keeps shared and proxy addresses out of counting and banning.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\IpSubject;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\ProxyTrust;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Decides whether a resolved client address may be counted and banned.
 *
 * When the real visitor address is hidden — a reverse proxy that is not
 * configured here, or a configured one whose forwarded header is missing so
 * IpDetector falls back to the proxy's own address — every visitor resolves
 * to the same address. Counting that address means a handful of failed logins
 * bans the whole site, administrators included. So an address that nobody on
 * the internet can be connecting from (private, reserved, loopback,
 * link-local, carrier-grade NAT) or that is a configured trusted proxy is
 * never counted or banned. It is still subject to the blacklist, whitelist,
 * geo and bot checks.
 *
 * The trade: while the proxy is unconfigured, per-client limits are off for
 * that traffic. The Status tab already warns about exactly this state.
 */
final class CountGuard {

	/**
	 * Shared address space (RFC 6598) — used by carrier-grade NAT and by
	 * internal load balancers; never a single visitor. PHP's reserved-range
	 * filter does not cover it.
	 */
	private const SHARED_RANGES = [ '100.64.0.0/10' ];

	/**
	 * Whether the address may be counted and banned, using the configured
	 * trusted proxies.
	 *
	 * @param string $ip Resolved client address.
	 * @return bool
	 */
	public static function allows( string $ip ): bool {
		return self::allows_for( $ip, (array) Options::get( 'trusted_proxies', [] ) );
	}

	/**
	 * Pure form of allows().
	 *
	 * An IPv4-mapped address is judged by its IPv4 part, so a dual-stack
	 * socket reporting "::ffff:8.8.8.8" is still counted.
	 *
	 * @param string             $ip      Resolved client address.
	 * @param array<int, string> $proxies Configured trusted proxy addresses/ranges.
	 * @return bool
	 */
	public static function allows_for( string $ip, array $proxies ): bool {
		$ip = IpSubject::unmap( trim( $ip ) );

		if ( ProxyTrust::is_non_routable( $ip ) || IpMatcher::matches( $ip, self::SHARED_RANGES ) ) {
			return false;
		}

		return ! ( ProxyTrust::is_configured( $proxies ) && IpMatcher::matches( $ip, $proxies ) );
	}
}
