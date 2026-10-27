<?php
/**
 * Tests for the profile-screen mount point.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\ProfileSection;

require_once dirname( __DIR__ ) . '/Support/WpUser.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\ProfileSection
 */
final class ProfileSectionTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubTranslationFunctions();
		Functions\stubEscapeFunctions();
		Functions\when( 'wp_json_encode' )->alias( static fn ( $d ) => json_encode( $d ) );
		Functions\when( 'get_current_user_id' )->justReturn( 5 );
		Functions\when( 'home_url' )->justReturn( 'https://example.com' );
		Functions\when( 'wp_parse_url' )->alias( static fn ( $url, $component = -1 ) => parse_url( (string) $url, $component ) );
	}

	private function render( int $user_id ): string {
		ob_start();
		( new ProfileSection() )->render( new \WP_User( $user_id, 'u' . $user_id ) );
		return (string) ob_get_clean();
	}

	public function test_own_profile_prints_the_mount_point_with_a_placeholder(): void {
		Functions\when( 'current_user_can' )->justReturn( false );
		$html = $this->render( 5 );

		$this->assertStringContainsString( 'id="lw-firewall-2fa"', $html );
		$this->assertStringContainsString( 'lwfw-2fa-placeholder', $html );
		$this->assertMatchesRegularExpression( '/data-config="[^"]*&quot;self&quot;:true/', $html );
	}

	public function test_another_users_profile_needs_edit_user(): void {
		Functions\when( 'current_user_can' )->justReturn( false );
		$this->assertSame( '', $this->render( 6 ) );

		Functions\when( 'current_user_can' )->justReturn( true );
		$html = $this->render( 6 );
		$this->assertMatchesRegularExpression( '/&quot;self&quot;:false/', $html );
		$this->assertMatchesRegularExpression( '/&quot;passkeys&quot;:false/', $html );
	}

	public function test_assets_load_only_on_the_profile_screens(): void {
		Functions\expect( 'wp_enqueue_script' )->never();
		( new ProfileSection() )->enqueue( 'index.php' );
		$this->addToAssertionCount( 1 );
	}
}
