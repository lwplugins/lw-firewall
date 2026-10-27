<?php
/**
 * Tests for the passwordless passkey button of the login form.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\PasskeyStubTrait;
use LightweightPlugins\Firewall\TwoFactor\PasskeyLoginButton;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\PasskeyLoginButton
 */
final class PasskeyLoginButtonTest extends MonkeyTestCase {

	use PasskeyStubTrait;

	protected function setUp(): void {
		parent::setUp();
		Functions\stubEscapeFunctions();
		Functions\when( 'rest_url' )->alias( static fn ( $path = '' ) => 'https://example.com/wp-json/' . ltrim( (string) $path, '/' ) );
		Functions\when( 'wp_enqueue_script' )->justReturn( null );
	}

	private function render(): string {
		ob_start();
		( new PasskeyLoginButton() )->render();
		return (string) ob_get_clean();
	}

	public function test_button_is_hidden_until_the_script_finds_webauthn(): void {
		$this->stub_passkey_wp();
		$html = $this->render();

		$this->assertMatchesRegularExpression( '/<div[^>]+id="lwfw-passkey-login"[^>]*\shidden/', $html );
		$this->assertStringContainsString( 'type="button"', $html );
		$this->assertStringContainsString( 'Sign in with a passkey', $html );
		$this->assertStringContainsString( '<svg', $html );
		$this->assertStringContainsString( 'stroke="currentColor"', $html );
		$this->assertStringContainsString( 'https://example.com/wp-json/lw-firewall/v1/passkey/login/options', $html );
		$this->assertStringContainsString( 'https://example.com/wp-json/lw-firewall/v1/passkey/login/verify', $html );
		$this->assertDoesNotMatchRegularExpression( '/[\x{1F300}-\x{1FAFF}\x{2713}\x{2714}]/u', $html, 'No emoji or check glyphs.' );
	}

	public function test_nothing_when_passkeys_are_unavailable(): void {
		$this->stub_passkey_wp( '' );

		$this->assertSame( '', $this->render() );
	}

	public function test_registers_on_the_login_form(): void {
		( new PasskeyLoginButton() )->register();

		$this->assertNotFalse( has_action( 'login_form' ) );
	}
}
