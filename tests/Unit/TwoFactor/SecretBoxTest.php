<?php
/**
 * Tests for the secret box.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\SecretBox;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\SecretBox
 */
final class SecretBoxTest extends MonkeyTestCase {

	private function salt( string $salt ): void {
		Functions\when( 'wp_salt' )->justReturn( $salt );
	}

	public function test_round_trip(): void {
		$this->salt( 'salt-one' );
		$sealed = SecretBox::seal( 'JBSWY3DPEHPK3PXP' );
		$this->assertNotSame( 'JBSWY3DPEHPK3PXP', $sealed );
		$this->assertSame( 'JBSWY3DPEHPK3PXP', SecretBox::open( $sealed ) );
	}

	public function test_seal_is_randomized(): void {
		$this->salt( 'salt-one' );
		$this->assertNotSame( SecretBox::seal( 'x' ), SecretBox::seal( 'x' ) );
	}

	public function test_modified_byte_returns_null(): void {
		$this->salt( 'salt-one' );
		$raw    = (string) base64_decode( SecretBox::seal( 'secret' ), true );
		$raw[ strlen( $raw ) - 1 ] = chr( ord( $raw[ strlen( $raw ) - 1 ] ) ^ 1 );
		$this->assertNull( SecretBox::open( base64_encode( $raw ) ) );
	}

	public function test_other_salt_returns_null(): void {
		$this->salt( 'salt-one' );
		$sealed = SecretBox::seal( 'secret' );
		$this->salt( 'salt-two' );
		$this->assertNull( SecretBox::open( $sealed ) );
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function garbage(): array {
		return array(
			'empty'      => array( '' ),
			'not base64' => array( '!!!not base64***' ),
			'too short'  => array( base64_encode( 'abc' ) ),
		);
	}

	/**
	 * @dataProvider garbage
	 */
	public function test_garbage_returns_null( string $input ): void {
		$this->salt( 'salt-one' );
		$this->assertNull( SecretBox::open( $input ) );
	}
}
