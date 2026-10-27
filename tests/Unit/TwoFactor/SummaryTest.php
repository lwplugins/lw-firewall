<?php
/**
 * Tests for the per-role two-factor summary.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\TwoFactor\Summary;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpUser.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\Summary
 */
final class SummaryTest extends MonkeyTestCase {

	use UserMetaStubTrait;

	/**
	 * Arguments of the last get_users() call.
	 *
	 * @var array<string, mixed>
	 */
	private array $query = array();

	protected function setUp(): void {
		parent::setUp();
		$this->stub_user_meta();
		Functions\stubTranslationFunctions();
		Functions\when( 'wp_salt' )->justReturn( 'salt' );
		Functions\when( 'home_url' )->justReturn( 'https://example.com' );
		Functions\when( 'wp_parse_url' )->alias( 'parse_url' );
		OptionStore::install( array( 'lw_firewall' => array( 'twofa_required_roles' => array( 'editor' ) ) ) );
		Functions\when( 'translate_user_role' )->alias( static fn ( $name ) => $name );
		Functions\when( 'wp_roles' )->justReturn(
			new class() {
				public function get_names(): array {
					return array(
						'administrator' => 'Administrator',
						'editor'        => 'Editor',
						'subscriber'    => 'Subscriber',
					);
				}
			}
		);
		Functions\when( 'count_users' )->justReturn(
			array(
				'total_users' => 40,
				'avail_roles' => array(
					'administrator' => 3,
					'editor'        => 7,
					'subscriber'    => 30,
					'none'          => 0,
				),
			)
		);
	}

	/**
	 * @param \WP_User[] $users Users the meta query returns.
	 */
	private function users( array $users ): void {
		Functions\when( 'get_users' )->alias(
			function ( array $args ) use ( $users ): array {
				$this->query = $args;
				return $users;
			}
		);
	}

	public function test_counts_users_with_a_factor_per_role(): void {
		$this->users(
			array(
				new \WP_User( 1, 'a', 'A', array( 'administrator' ) ),
				new \WP_User( 2, 'b', 'B', array( 'editor' ) ),
				new \WP_User( 3, 'c', 'C', array( 'editor' ) ),
			)
		);
		( new UserFactors( 1 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );
		( new UserFactors( 2 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );
		// User 3 only has an emptied passkey list: no factor.
		update_user_meta( 3, UserFactors::META_PASSKEYS, array() );

		$out   = Summary::build();
		$roles = array_column( $out['roles'], null, 'role' );

		$this->assertSame( 40, $out['total_users'] );
		$this->assertSame( 2, $out['total_with_2fa'] );
		$this->assertFalse( $out['truncated'] );
		$this->assertSame( 3, $roles['administrator']['users'] );
		$this->assertSame( 1, $roles['administrator']['with_2fa'] );
		$this->assertFalse( $roles['administrator']['required'] );
		$this->assertSame( 7, $roles['editor']['users'] );
		$this->assertSame( 1, $roles['editor']['with_2fa'] );
		$this->assertTrue( $roles['editor']['required'] );
		$this->assertSame( 0, $roles['subscriber']['with_2fa'] );
		$this->assertSame( 'Editor', $roles['editor']['label'] );
	}

	public function test_one_bounded_query_for_users_with_any_factor_meta(): void {
		$this->users( array() );

		Summary::build();

		$this->assertSame( 'OR', $this->query['meta_query']['relation'] );
		$keys = array_column( array_filter( $this->query['meta_query'], 'is_array' ), 'key' );
		$this->assertContains( UserFactors::META_TOTP, $keys );
		$this->assertContains( UserFactors::META_PASSKEYS, $keys );
		$this->assertSame( Summary::LIMIT, $this->query['number'] );
	}

	public function test_flags_a_truncated_sample(): void {
		$users = array();
		for ( $i = 1; $i <= Summary::LIMIT; $i++ ) {
			$users[] = new \WP_User( $i, 'u', 'U', array( 'subscriber' ) );
		}
		$this->users( $users );

		$this->assertTrue( Summary::build()['truncated'] );
	}

	public function test_response_carries_no_secrets_and_reports_capabilities(): void {
		$this->users( array( new \WP_User( 1, 'a', 'A', array( 'administrator' ) ) ) );
		( new UserFactors( 1 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );

		$out = Summary::build();

		$this->assertIsBool( $out['passkeys_available'] );
		$this->assertIsBool( $out['crypto_available'] );
		$this->assertStringNotContainsString( 'JBSWY3DPEHPK3PXP', (string) json_encode( $out ) );
	}
}
