<?php
/**
 * Lifts bans and reports each outcome.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Bans;

use LightweightPlugins\Firewall\IpSubject;
use LightweightPlugins\Firewall\Rules\AutoBanner;
use LightweightPlugins\Firewall\Rules\BanList;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Per-address unban results — never a blanket success. An address whose
 * delete the storage refused stays in the index, so it is still listed.
 */
final class Unbanner {

	/**
	 * Constructor.
	 *
	 * @param AutoBanner $banner Ban writer bound to the active storage.
	 */
	public function __construct( private AutoBanner $banner ) {
	}

	/**
	 * Lift the given targets.
	 *
	 * @param array<int, mixed> $targets IPs or IPv6 /64 subject keys.
	 * @return array<int, array{ip: string, ok: bool, message: string}>
	 */
	public function lift( array $targets ): array {
		$results = [];

		foreach ( $targets as $target ) {
			$target    = is_scalar( $target ) ? trim( (string) $target ) : '';
			$results[] = $this->lift_one( $target );
		}

		return $results;
	}

	/**
	 * Lift every tracked ban.
	 *
	 * @return array<int, array{ip: string, ok: bool, message: string}>
	 */
	public function lift_all(): array {
		return $this->lift( BanList::ips() );
	}

	/**
	 * Lift one target.
	 *
	 * @param string $target IP or subject key.
	 * @return array{ip: string, ok: bool, message: string}
	 */
	private function lift_one( string $target ): array {
		if ( '' === IpSubject::parse( $target ) ) {
			return self::result( $target, false, __( 'That is not a valid IP address.', 'lw-firewall' ) );
		}

		if ( ! $this->banner->unban( $target ) ) {
			return self::result( $target, false, __( 'The ban could not be lifted — the storage backend refused the delete. Check the Status tab for the active backend.', 'lw-firewall' ) );
		}

		return self::result( $target, true, __( 'Unblocked. Its rate-limit, login, registration and password-reset counters were cleared too, so the next request starts from zero.', 'lw-firewall' ) );
	}

	/**
	 * One result row.
	 *
	 * @param string $ip      Target as given.
	 * @param bool   $ok      Whether it is unbanned now.
	 * @param string $message Human-readable outcome.
	 * @return array{ip: string, ok: bool, message: string}
	 */
	private static function result( string $ip, bool $ok, string $message ): array {
		return [
			'ip'      => $ip,
			'ok'      => $ok,
			'message' => $message,
		];
	}
}
