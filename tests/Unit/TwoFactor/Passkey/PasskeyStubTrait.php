<?php
/**
 * WordPress stubs shared by the passkey tests (transients, site URL, i18n).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey;

use Brain\Monkey\Functions;

/**
 * In-memory transients plus the site/i18n functions the passkey classes call.
 */
trait PasskeyStubTrait {

	/**
	 * Transient store: [ name => [ value, ttl ] ].
	 *
	 * @var array<string, array{0: mixed, 1: int}>
	 */
	protected array $transients = array();

	protected function stub_passkey_wp( string $home = 'https://example.com' ): void {
		$this->transients = array();
		$store            = &$this->transients;

		Functions\when( 'set_transient' )->alias(
			static function ( $name, $value, $ttl = 0 ) use ( &$store ) {
				$store[ $name ] = array( $value, (int) $ttl );
				return true;
			}
		);
		Functions\when( 'get_transient' )->alias(
			static function ( $name ) use ( &$store ) {
				return isset( $store[ $name ] ) ? $store[ $name ][0] : false;
			}
		);
		Functions\when( 'delete_transient' )->alias(
			static function ( $name ) use ( &$store ) {
				if ( ! isset( $store[ $name ] ) ) {
					return false;
				}
				unset( $store[ $name ] );
				return true;
			}
		);
		Functions\when( 'home_url' )->justReturn( $home );
		Functions\when( 'get_bloginfo' )->justReturn( 'Example &amp; Co' );
		Functions\when( 'wp_specialchars_decode' )->alias( static fn ( $s, $q = 0 ) => htmlspecialchars_decode( (string) $s, ENT_QUOTES ) );
		Functions\when( 'wp_parse_url' )->alias( static fn ( $url, $component = -1 ) => parse_url( (string) $url, $component ) );
		Functions\when( 'wp_json_encode' )->alias( static fn ( $data, $flags = 0 ) => json_encode( $data, $flags ) );
		Functions\when( 'wp_strip_all_tags' )->alias( static fn ( $s ) => strip_tags( (string) $s ) );
		Functions\stubTranslationFunctions();
	}
}
