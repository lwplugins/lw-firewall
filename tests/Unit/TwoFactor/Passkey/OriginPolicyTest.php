<?php
/**
 * Tests for the exact-origin policy.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey;

use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\Passkey\OriginPolicy;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\Passkey\OriginPolicy
 */
final class OriginPolicyTest extends MonkeyTestCase {

	use PasskeyStubTrait;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_passkey_wp( 'https://Example.com/blog/', 'https://example.com:443/blog/wp' );
	}

	public function test_origins_are_home_and_site_deduped(): void {
		$this->assertSame( array( 'https://example.com' ), OriginPolicy::origins() );
	}

	public function test_exact_match_only(): void {
		$this->assertTrue( OriginPolicy::allowed( 'https://example.com' ) );
		$this->assertTrue( OriginPolicy::allowed( 'https://EXAMPLE.com:443' ) );
		$this->assertFalse( OriginPolicy::allowed( 'https://evilexample.com' ) );
		$this->assertFalse( OriginPolicy::allowed( 'https://sub.example.com' ) );
		$this->assertFalse( OriginPolicy::allowed( 'https://example.com:8443' ) );
		$this->assertFalse( OriginPolicy::allowed( 'http://example.com' ) );
		$this->assertFalse( OriginPolicy::allowed( 'https://example.com/path' ) );
		$this->assertFalse( OriginPolicy::allowed( 'https://user@example.com' ) );
		$this->assertFalse( OriginPolicy::allowed( 'android:apk-key-hash:abc' ) );
		$this->assertFalse( OriginPolicy::allowed( '' ) );
	}

	public function test_site_url_on_admin_subdomain_with_port(): void {
		$this->stub_passkey_wp( 'https://example.com', 'https://admin.example.com:8443' );
		$this->assertSame( array( 'https://example.com', 'https://admin.example.com:8443' ), OriginPolicy::origins() );
		$this->assertTrue( OriginPolicy::allowed( 'https://admin.example.com:8443' ) );
		$this->assertFalse( OriginPolicy::allowed( 'https://admin.example.com' ) );
	}

	public function test_site_url_outside_rp_id_is_dropped(): void {
		$this->stub_passkey_wp( 'https://example.com', 'https://other.net' );
		$this->assertSame( array( 'https://example.com' ), OriginPolicy::origins() );
	}

	public function test_filter_adds_validated_origins(): void {
		Filters\expectApplied( OriginPolicy::FILTER )->andReturn(
			array( 'https://shop.example.com/', 'https://evil.net', 'http://www.example.com', 'https://x.example.com/p', 42, 'https://example.com' )
		);
		$this->assertSame( array( 'https://example.com', 'https://shop.example.com' ), OriginPolicy::origins() );
	}

	public function test_non_array_filter_value_is_ignored(): void {
		Filters\expectApplied( OriginPolicy::FILTER )->andReturn( 'https://shop.example.com' );
		$this->assertSame( array( 'https://example.com' ), OriginPolicy::origins() );
	}

	public function test_localhost_allows_http_with_port(): void {
		Functions\when( 'home_url' )->justReturn( 'http://localhost:8080' );
		Functions\when( 'site_url' )->justReturn( 'http://localhost:8080' );
		$this->assertTrue( OriginPolicy::allowed( 'http://localhost:8080' ) );
		$this->assertFalse( OriginPolicy::allowed( 'http://localhost' ) );
	}
}
