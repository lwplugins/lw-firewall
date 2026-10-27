<?php
/**
 * Tests for the WebAuthn factory / relying-party settings.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\Passkey\WebAuthnFactory;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\Passkey\WebAuthnFactory
 */
final class WebAuthnFactoryTest extends MonkeyTestCase {

	use PasskeyStubTrait;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_passkey_wp( 'https://Example.COM/blog/' );
	}

	public function test_rp_id_is_lowercased_home_host(): void {
		$this->assertSame( 'example.com', WebAuthnFactory::rp_id() );
	}

	public function test_creates_unprefixed_library_in_dev(): void {
		$this->assertTrue( WebAuthnFactory::available() );
		$lib = WebAuthnFactory::create();
		$this->assertInstanceOf( \lbuchs\WebAuthn\WebAuthn::class, $lib );

		$args = $lib->getGetArgs( array(), 120, true, true, true, true, true, true );
		$this->assertSame( 'example.com', $args->publicKey->rpId );
		$json = json_decode( (string) json_encode( $args ), true );
		$this->assertMatchesRegularExpression( '/^[A-Za-z0-9_-]{43}$/', $json['publicKey']['challenge'] );

		$create = $lib->getCreateArgs( 'u', 'u', 'u' );
		$this->assertSame( 'Example & Co', $create->publicKey->rp->name );
	}

	public function test_create_fails_without_host(): void {
		Functions\when( 'home_url' )->justReturn( '' );
		$this->expectException( \RuntimeException::class );
		WebAuthnFactory::create();
	}

	public function test_origin_must_be_rp_or_subdomain_over_https(): void {
		$this->assertTrue( WebAuthnFactory::origin_allowed( 'https://example.com' ) );
		$this->assertTrue( WebAuthnFactory::origin_allowed( 'https://www.example.com' ) );
		$this->assertTrue( WebAuthnFactory::origin_allowed( 'https://EXAMPLE.com:8443' ) );
		$this->assertFalse( WebAuthnFactory::origin_allowed( 'http://example.com' ) );
		$this->assertFalse( WebAuthnFactory::origin_allowed( 'https://evilexample.com' ) );
		$this->assertFalse( WebAuthnFactory::origin_allowed( 'https://example.com.evil.net' ) );
		$this->assertFalse( WebAuthnFactory::origin_allowed( 'android:apk-key-hash:abc' ) );
		$this->assertFalse( WebAuthnFactory::origin_allowed( '' ) );
	}

	public function test_localhost_allows_http(): void {
		Functions\when( 'home_url' )->justReturn( 'http://localhost:8080' );
		$this->assertTrue( WebAuthnFactory::origin_allowed( 'http://localhost:8080' ) );
	}
}
