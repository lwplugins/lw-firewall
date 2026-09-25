<?php
/**
 * Round-trip check of the active storage backend.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Status;

use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Writes, reads back and deletes a probe key. Every tracker fails open when
 * the storage refuses a write, which is silent at runtime — this makes it
 * visible.
 */
final class StorageProbe {

	/**
	 * Run the probe.
	 *
	 * @param StorageInterface $storage Active backend.
	 * @return array{ok: bool, message: string}
	 */
	public static function run( StorageInterface $storage ): array {
		$key   = 'status_probe_' . bin2hex( random_bytes( 6 ) );
		$token = bin2hex( random_bytes( 8 ) );

		if ( ! $storage->set( $key, $token, 60 ) ) {
			return self::result( false, __( 'The storage backend refused a write. Rate limits, bans and counters are not being recorded.', 'lw-firewall' ) );
		}

		if ( $storage->get( $key ) !== $token ) {
			$storage->delete( $key );
			return self::result( false, __( 'A value written to the storage backend could not be read back. Rate limits, bans and counters are not being enforced.', 'lw-firewall' ) );
		}

		$storage->delete( $key );

		if ( null !== $storage->get( $key ) ) {
			return self::result( false, __( 'The storage backend refused a delete. Unblocking an address may not take effect.', 'lw-firewall' ) );
		}

		return self::result( true, __( 'Write, read and delete all succeeded.', 'lw-firewall' ) );
	}

	/**
	 * The result shape.
	 *
	 * @param bool   $ok      Whether the round trip succeeded.
	 * @param string $message Human-readable outcome.
	 * @return array{ok: bool, message: string}
	 */
	private static function result( bool $ok, string $message ): array {
		return [
			'ok'      => $ok,
			'message' => $message,
		];
	}
}
