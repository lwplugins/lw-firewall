<?php
/**
 * Keeps an administrator from banning their own address.
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
 * A ban is enforced by the worker before WordPress loads, wp-admin
 * included, so banning the address in use would lock the administrator out
 * for the whole ban.
 */
final class SelfBanGuard {

	/**
	 * Whether the target is (or covers) the administrator's own address.
	 *
	 * @param string $target  Requested ban (an IP or an IPv6 /64 key).
	 * @param string $current The administrator's resolved address.
	 * @return bool
	 */
	public static function is_own_address( string $target, string $current ): bool {
		$target = trim( $target );

		return '' !== $target && '' !== $current && IpSubject::of( $target ) === IpSubject::of( $current );
	}
}
