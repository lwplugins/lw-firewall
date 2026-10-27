<?php
/**
 * Tests for the two-factor module bootstrap.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\TwoFactorModule;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\TwoFactorModule
 */
final class TwoFactorModuleTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubTranslationFunctions();
		Functions\stubEscapeFunctions();
		Functions\when( 'sanitize_key' )->alias( static fn ( $k ) => (string) preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $k ) ) );
	}

	public function test_off_by_default_registers_nothing(): void {
		Functions\when( 'get_option' )->justReturn( array() );

		TwoFactorModule::init();

		$this->assertFalse( has_action( 'wp_login' ) );
		$this->assertFalse( has_filter( 'authenticate' ) );
		$this->assertFalse( has_action( 'admin_notices' ) );
	}

	public function test_enabled_registers_the_login_hooks(): void {
		Functions\when( 'get_option' )->justReturn( array( 'twofa_enabled' => true ) );

		TwoFactorModule::init();

		$this->assertTrue( has_action( 'wp_login' ) );
		$this->assertTrue( has_action( 'login_form_lw_firewall_2fa' ) );
		$this->assertTrue( has_filter( 'send_auth_cookies' ) );
		$this->assertTrue( has_filter( 'authenticate' ) );
		$this->assertFalse( has_filter( 'wp_is_application_passwords_available_for_user' ) );
	}

	public function test_blocking_app_passwords_is_wired(): void {
		Functions\when( 'get_option' )->justReturn( array( 'twofa_enabled' => true, 'twofa_block_app_passwords' => true ) );

		TwoFactorModule::init();

		$this->assertTrue( has_filter( 'wp_is_application_passwords_available_for_user' ) );
	}

	public function test_missing_crypto_shows_a_notice_instead(): void {
		$this->assertFalse( TwoFactorModule::boot( true, false ) );

		$this->assertFalse( has_action( 'wp_login' ) );
		$this->assertNotFalse( has_action( 'admin_notices', array( TwoFactorModule::class, 'render_unavailable_notice' ) ) );
	}

	public function test_this_environment_has_the_extensions(): void {
		$this->assertTrue( TwoFactorModule::crypto_available() );
	}

	public function test_notice_is_for_administrators_only(): void {
		Functions\when( 'current_user_can' )->justReturn( false );
		ob_start();
		TwoFactorModule::render_unavailable_notice();
		$this->assertSame( '', ob_get_clean() );

		Functions\when( 'current_user_can' )->justReturn( true );
		ob_start();
		TwoFactorModule::render_unavailable_notice();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'dashicons-warning', $html );
		$this->assertStringContainsString( 'sodium', $html );
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_the_wp_config_constant_pins_it_off(): void {
		define( 'LW_FIREWALL_TWOFA_ENABLED', false );
		Functions\when( 'get_option' )->justReturn( array( 'twofa_enabled' => true ) );

		TwoFactorModule::init();

		$this->assertFalse( has_action( 'wp_login' ) );
		$this->assertFalse( has_filter( 'authenticate' ) );
	}
}
