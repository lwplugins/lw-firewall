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

	public function test_isolated_restores_the_global_encoding_flag(): void {
		\lbuchs\WebAuthn\Binary\ByteBuffer::$useBase64UrlEncoding = false;
		$json = WebAuthnFactory::isolated(
			static function (): string {
				$lib = WebAuthnFactory::create();
				return (string) json_encode( $lib->getGetArgs() );
			}
		);
		$this->assertFalse( \lbuchs\WebAuthn\Binary\ByteBuffer::$useBase64UrlEncoding );
		$this->assertStringNotContainsString( '=?BINARY?', $json );

		try {
			WebAuthnFactory::isolated(
				static function (): void {
					WebAuthnFactory::create();
					throw new \RuntimeException( 'boom' );
				}
			);
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'boom', $e->getMessage() );
		}
		$this->assertFalse( \lbuchs\WebAuthn\Binary\ByteBuffer::$useBase64UrlEncoding );
	}
}
