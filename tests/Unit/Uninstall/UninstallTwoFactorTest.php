<?php
/**
 * Tests that uninstall removes the two-factor user meta.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Uninstall;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\FakeWpdb;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;

require_once dirname( __DIR__ ) . '/Support/FakeWpdb.php';

/**
 * @coversNothing
 */
final class UninstallTwoFactorTest extends MonkeyTestCase {

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_every_two_factor_meta_row_is_removed_and_others_kept(): void {
		define( 'WP_UNINSTALL_PLUGIN', 'lw-firewall/lw-firewall.php' );
		define( 'WPMU_PLUGIN_DIR', sys_get_temp_dir() . '/lwfw-none-mu' );
		define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/lwfw-none-content' );
		$deleted = array();
		Functions\when( 'delete_option' )->alias(
			static function ( $name ) use ( &$deleted ) {
				$deleted[] = $name;
				return true;
			}
		);
		Functions\when( 'delete_transient' )->justReturn( true );
		Functions\when( 'wp_next_scheduled' )->justReturn( false );
		Functions\when( 'wp_clear_scheduled_hook' )->justReturn( 0 );
		Functions\when( 'wp_cache_flush_group' )->justReturn( true );

		global $wpdb;
		$wpdb = new FakeWpdb();
		$keys = array(
			'_lw_firewall_totp',
			'_lw_firewall_recovery',
			'_lw_firewall_passkeys',
			'_lw_firewall_passkey_lookup',
			'_lw_firewall_user_handle',
			'_lw_firewall_remember_salt',
			'_lw_firewall_2fa_since',
			'_lw_firewall_2fa_fail',
			'_lw_firewall_2fa_bind',
			'_lw_firewall_2fa_tok_0123456789abcdef',
			'first_name',
			'_lw_firewallXtotp',
		);
		foreach ( array( 3, 4 ) as $user ) {
			foreach ( $keys as $key ) {
				$wpdb->query( $wpdb->prepare( 'INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (%d, %s, %s)', $user, $key, 'x' ) );
			}
		}

		require dirname( __DIR__, 3 ) . '/uninstall.php';

		$this->assertSame( array( 'first_name', '_lw_firewallXtotp', 'first_name', '_lw_firewallXtotp' ), array_column( $wpdb->rows(), 'meta_key' ) );
		$this->assertContains( 'lw_firewall_2fa_mail_failed', $deleted );
	}
}
