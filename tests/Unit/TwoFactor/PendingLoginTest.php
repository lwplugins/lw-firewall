<?php
/**
 * Tests for the pending (password-only) login store.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey\PasskeyStubTrait;
use LightweightPlugins\Firewall\TwoFactor\PendingLogin;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\PendingLogin
 */
final class PendingLoginTest extends MonkeyTestCase {

	use PasskeyStubTrait;

	private int $now = 1000000;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_passkey_wp();
	}

	private function store( string $ip = '203.0.113.7' ): PendingLogin {
		return new PendingLogin( $ip, fn (): int => $this->now );
	}

	public function test_create_stores_only_the_hash_of_the_token(): void {
		$token = $this->store()->create( 7, true, 'https://example.com/wp-admin/' );

		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/D', $token );
		$this->assertSame( array( 'lwfw_2fa_' . hash( 'sha256', $token ) ), array_keys( $this->transients ) );
		$this->assertSame( 300, $this->transients[ 'lwfw_2fa_' . hash( 'sha256', $token ) ][1] );

		$record = $this->store()->get( $token );
		$this->assertNotNull( $record );
		$this->assertSame( 7, $record['user_id'] );
		$this->assertTrue( $record['remember'] );
		$this->assertSame( 'https://example.com/wp-admin/', $record['redirect_to'] );
		$this->assertSame( '203.0.113.7', $record['ip_key'] );
		$this->assertSame( 0, $record['attempts'] );
	}

	public function test_another_ip_gets_nothing(): void {
		$token = $this->store()->create( 7, false, '' );

		$this->assertNull( $this->store( '198.51.100.1' )->get( $token ) );
		$this->assertNull( $this->store( '198.51.100.1' )->consume( $token ) );
		$this->assertNotNull( $this->store()->get( $token ), 'A foreign IP must not burn the token.' );
	}

	public function test_ipv6_is_keyed_by_its_64(): void {
		$token = $this->store( '2001:db8:1:1::5' )->create( 7, false, '' );

		$this->assertNotNull( $this->store( '2001:db8:1:1:ffff::9' )->get( $token ) );
		$this->assertNull( $this->store( '2001:db8:1:2::5' )->get( $token ) );
	}

	public function test_malformed_or_unknown_tokens_are_rejected(): void {
		$this->store()->create( 7, false, '' );

		$this->assertNull( $this->store()->get( '' ) );
		$this->assertNull( $this->store()->get( 'ZZZ' ) );
		$this->assertNull( $this->store()->get( str_repeat( 'a', 32 ) ) );
		$this->assertNull( $this->store()->get( str_repeat( 'a', 32 ) . "\n" ) );
	}

	public function test_consume_is_single_use(): void {
		$token = $this->store()->create( 7, false, '/x' );

		$record = $this->store()->consume( $token );
		$this->assertSame( 7, $record['user_id'] ?? null );
		$this->assertNull( $this->store()->consume( $token ) );
		$this->assertNull( $this->store()->get( $token ) );
		$this->assertSame( array(), $this->transients );
	}

	public function test_five_failures_delete_the_token(): void {
		$store = $this->store();
		$token = $store->create( 7, false, '' );

		$this->assertSame( 4, $store->fail( $token ) );
		$this->assertSame( 3, $store->fail( $token ) );
		$this->assertSame( 2, $store->fail( $token ) );
		$this->assertSame( 1, $store->fail( $token ) );
		$this->assertSame( 0, $store->fail( $token ) );
		$this->assertNull( $store->get( $token ) );
		$this->assertSame( array(), $this->transients );
		$this->assertSame( 0, $store->fail( $token ) );
	}

	public function test_a_failure_does_not_extend_the_lifetime(): void {
		$store = $this->store();
		$token = $store->create( 7, false, '' );

		$this->now += 200;
		$store->fail( $token );
		$this->assertSame( 100, $this->transients[ 'lwfw_2fa_' . hash( 'sha256', $token ) ][1] );

		$this->now += 101;
		$this->assertNull( $store->get( $token ), 'Expired even if the transient row outlived its TTL.' );
	}

	public function test_attach_passkey_key_is_kept_server_side(): void {
		$store = $this->store();
		$token = $store->create( 7, false, '' );

		$this->assertTrue( $store->attach_passkey( $token, str_repeat( 'b', 32 ) ) );
		$this->assertSame( str_repeat( 'b', 32 ), $store->get( $token )['passkey_key'] ?? null );
		$this->assertFalse( $store->attach_passkey( str_repeat( 'c', 32 ), 'x' ) );
	}
}
