<?php
/**
 * Tests for the "not network-activated" warning.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\NetworkActivationNotice;

/**
 * Condition matrix and capability gating.
 */
final class NetworkActivationNoticeTest extends MonkeyTestCase {

	/**
	 * Define the plugin file constant once.
	 */
	protected function setUp(): void {
		parent::setUp();
		if ( ! defined( 'LW_FIREWALL_FILE' ) ) {
			define( 'LW_FIREWALL_FILE', '/wp/plugins/lw-firewall/lw-firewall.php' );
		}
		Functions\when( 'plugin_basename' )->justReturn( 'lw-firewall/lw-firewall.php' );
		Functions\when( 'esc_html' )->returnArg();
		Functions\when( 'esc_url' )->returnArg();
		Functions\when( 'network_admin_url' )->alias( static fn ( $p = '' ) => 'https://x.test/wp-admin/network/' . $p );
		Functions\when( '__' )->returnArg();
		Functions\when( 'esc_html_e' )->alias(
			static function ( $t ) {
				echo $t; // phpcs:ignore WordPress.Security.EscapeOutput
			}
		);
	}

	/**
	 * Arrange the environment.
	 *
	 * @param bool $multisite Whether multisite.
	 * @param bool $enabled   Whether twofa_enabled.
	 * @param bool $network   Whether network-activated.
	 */
	private function arrange( bool $multisite, bool $enabled, bool $network ): void {
		Functions\when( 'is_multisite' )->justReturn( $multisite );
		Functions\when( 'is_main_site' )->justReturn( true );
		Functions\when( 'get_option' )->justReturn( array( 'twofa_enabled' => $enabled ) );
		Functions\when( 'is_plugin_active_for_network' )->justReturn( $network );
	}

	/**
	 * Single site: never.
	 */
	public function test_single_site_none(): void {
		$this->arrange( false, true, false );
		$this->assertFalse( NetworkActivationNotice::required() );
	}

	/**
	 * Multisite, on, per-site active: warn.
	 */
	public function test_multisite_enabled_not_network_active(): void {
		$this->arrange( true, true, false );
		$this->assertTrue( NetworkActivationNotice::required() );
	}

	/**
	 * Network-activated: none.
	 */
	public function test_network_active_none(): void {
		$this->arrange( true, true, true );
		$this->assertFalse( NetworkActivationNotice::required() );
	}

	/**
	 * Disabled: none.
	 */
	public function test_disabled_none(): void {
		$this->arrange( true, false, false );
		$this->assertFalse( NetworkActivationNotice::required() );
	}

	/**
	 * Main site: manage_options only, no link without network caps, not on subsites.
	 */
	public function test_site_notice_caps_and_main_site(): void {
		$this->arrange( true, true, false );
		Functions\when( 'is_main_site' )->justReturn( true );
		Functions\when( 'current_user_can' )->alias( static fn ( $c ) => 'manage_options' === $c );
		ob_start();
		( new NetworkActivationNotice() )->render_site();
		$out = (string) ob_get_clean();
		$this->assertStringContainsString( 'not network-activated', $out );
		$this->assertStringNotContainsString( 'plugins.php', $out );

		Functions\when( 'current_user_can' )->justReturn( true );
		ob_start();
		( new NetworkActivationNotice() )->render_site();
		$this->assertStringContainsString( 'network/plugins.php', (string) ob_get_clean() );

		Functions\when( 'current_user_can' )->justReturn( false );
		ob_start();
		( new NetworkActivationNotice() )->render_site();
		$this->assertSame( '', ob_get_clean() );

		Functions\when( 'is_main_site' )->justReturn( false );
		Functions\when( 'current_user_can' )->justReturn( true );
		ob_start();
		( new NetworkActivationNotice() )->render_site();
		$this->assertSame( '', ob_get_clean() );
	}

	/**
	 * No notice when the condition is false even for capable users.
	 */
	public function test_no_output_when_not_required(): void {
		$this->arrange( true, true, true );
		Functions\when( 'is_main_site' )->justReturn( true );
		Functions\when( 'current_user_can' )->justReturn( true );
		ob_start();
		( new NetworkActivationNotice() )->render_site();
		$this->assertSame( '', ob_get_clean() );
	}
}
