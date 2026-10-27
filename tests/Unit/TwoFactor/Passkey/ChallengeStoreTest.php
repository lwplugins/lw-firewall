<?php
/**
 * Tests for the single-use challenge store.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey;

use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\TwoFactor\Passkey\ChallengeStore;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\Passkey\ChallengeStore
 */
final class ChallengeStoreTest extends MonkeyTestCase {

	use PasskeyStubTrait;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_passkey_wp();
	}

	public function test_put_returns_hex_key_and_stores_text_safe_value_for_120s(): void {
		$bin = "\x00\xff" . random_bytes( 30 );
		$key = ChallengeStore::put( 'register', $bin, 7 );

		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $key );
		$this->assertArrayHasKey( 'lwfw_pk_' . $key, $this->transients );
		$this->assertSame( 120, $this->transients[ 'lwfw_pk_' . $key ][1] );
		$this->assertStringNotContainsString( $bin, serialize( $this->transients[ 'lwfw_pk_' . $key ][0] ) );
	}

	public function test_take_returns_once(): void {
		$bin = random_bytes( 32 );
		$key = ChallengeStore::put( 'assert', $bin, 3 );

		$this->assertSame(
			array(
				'challenge' => $bin,
				'user_id'   => 3,
			),
			ChallengeStore::take( $key, 'assert' )
		);
		$this->assertNull( ChallengeStore::take( $key, 'assert' ) );
	}

	public function test_wrong_purpose_is_null_and_still_consumes(): void {
		$key = ChallengeStore::put( 'register', random_bytes( 32 ), 3 );

		$this->assertNull( ChallengeStore::take( $key, 'assert' ) );
		$this->assertNull( ChallengeStore::take( $key, 'register' ) );
	}

	public function test_malformed_and_unknown_keys(): void {
		$this->assertNull( ChallengeStore::take( 'not-a-key', 'assert' ) );
		$this->assertNull( ChallengeStore::take( str_repeat( 'a', 32 ), 'assert' ) );
	}

	public function test_lost_delete_race_is_null(): void {
		$key = ChallengeStore::put( 'assert', random_bytes( 32 ) );
		\Brain\Monkey\Functions\when( 'delete_transient' )->justReturn( false );

		$this->assertNull( ChallengeStore::take( $key, 'assert' ) );
	}

	public function test_corrupt_stored_value_is_null(): void {
		$this->transients[ 'lwfw_pk_' . str_repeat( 'b', 32 ) ] = array(
			array(
				'purpose'   => 'assert',
				'challenge' => 'zz',
				'user_id'   => 1,
			),
			120,
		);
		$this->assertNull( ChallengeStore::take( str_repeat( 'b', 32 ), 'assert' ) );
	}
}
