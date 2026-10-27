<?php
/**
 * In-memory user meta stub for Brain Monkey tests.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;

/**
 * Backs get/add/update/delete_user_meta and get_users (meta lookup) with an array.
 * Call stub_user_meta() in the test (or setUp); storage is fresh per call.
 */
trait UserMetaStubTrait {

	/**
	 * Rows per user and key: [ user_id => [ key => [ value, ... ] ] ].
	 *
	 * @var array<int, array<string, array<int, mixed>>>
	 */
	protected array $user_meta = array();

	protected function stub_user_meta(): void {
		$this->user_meta = array();
		$store           = &$this->user_meta;

		Functions\when( 'get_user_meta' )->alias(
			static function ( $user_id, $key = '', $single = false ) use ( &$store ) {
				$rows = $store[ (int) $user_id ][ $key ] ?? array();
				if ( $single ) {
					return $rows[0] ?? '';
				}
				return $rows;
			}
		);
		Functions\when( 'add_user_meta' )->alias(
			static function ( $user_id, $key, $value, $unique = false ) use ( &$store ) {
				$rows = $store[ (int) $user_id ][ $key ] ?? array();
				if ( $unique && $rows ) {
					return false;
				}
				$store[ (int) $user_id ][ $key ][] = $value;
				return count( $store[ (int) $user_id ][ $key ] );
			}
		);
		Functions\when( 'update_user_meta' )->alias(
			static function ( $user_id, $key, $value, $prev = '' ) use ( &$store ) {
				$store[ (int) $user_id ][ $key ] = array( $value );
				return true;
			}
		);
		Functions\when( 'delete_user_meta' )->alias(
			static function ( $user_id, $key, $value = '' ) use ( &$store ) {
				$rows = $store[ (int) $user_id ][ $key ] ?? array();
				if ( ! $rows ) {
					return false;
				}
				if ( '' === $value ) {
					unset( $store[ (int) $user_id ][ $key ] );
					return true;
				}
				$kept = array_values(
					array_filter(
						$rows,
						static fn ( $row ) => $row !== $value
					)
				);
				if ( $kept ) {
					$store[ (int) $user_id ][ $key ] = $kept;
				} else {
					unset( $store[ (int) $user_id ][ $key ] );
				}
				return count( $kept ) !== count( $rows );
			}
		);
		Functions\when( 'get_users' )->alias(
			static function ( $args = array() ) use ( &$store ) {
				$ids = array();
				foreach ( $store as $uid => $keys ) {
					$rows = $keys[ $args['meta_key'] ?? '' ] ?? array();
					if ( in_array( $args['meta_value'] ?? null, $rows, true ) ) {
						$ids[] = $uid;
					}
				}
				return array_slice( $ids, 0, (int) ( $args['number'] ?? count( $ids ) ) );
			}
		);
	}
}
