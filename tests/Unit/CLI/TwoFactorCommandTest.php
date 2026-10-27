<?php
/**
 * Tests for `wp lw-firewall 2fa`.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\CLI;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\CLI\TwoFactorCommand;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\UserMetaStubTrait;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpUser.php';
require_once dirname( __DIR__ ) . '/Support/WpCli.php';

/**
 * @covers \LightweightPlugins\Firewall\CLI\TwoFactorCommand
 */
final class TwoFactorCommandTest extends MonkeyTestCase {

	use UserMetaStubTrait;

	/**
	 * Rows handed to WP_CLI\Utils\format_items().
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private array $table = array();

	protected function setUp(): void {
		parent::setUp();
		\WP_CLI::reset();
		$this->table = array();
		$this->stub_user_meta();
		Functions\stubTranslationFunctions();
		Functions\when( 'wp_salt' )->justReturn( 'salt' );
		OptionStore::install( array() );
		Functions\when( 'get_user_by' )->alias(
			static function ( string $field, $value ) {
				if ( 'login' === $field && 'alice' === $value ) {
					return new \WP_User( 5, 'alice', 'Alice', array( 'editor' ) );
				}
				if ( 'id' === $field && 5 === (int) $value ) {
					return new \WP_User( 5, 'alice', 'Alice', array( 'editor' ) );
				}
				return false;
			}
		);
		Functions\when( 'WP_CLI\Utils\format_items' )->alias(
			function ( string $format, array $items ): void {
				$this->table = $items;
			}
		);
		Functions\when( 'WP_CLI\Utils\get_flag_value' )->alias(
			static fn ( array $args, string $flag, $default = null ) => $args[ $flag ] ?? $default
		);
	}

	public function test_reset_stops_on_an_unknown_user(): void {
		( new UserFactors( 5 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );

		try {
			( new TwoFactorCommand() )->reset( array( 'nobody' ), array( 'yes' => true ) );
			$this->fail( 'Expected an error.' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringContainsString( 'nobody', $e->getMessage() );
		}

		$this->assertTrue( ( new UserFactors( 5 ) )->has_any() );
	}

	public function test_reset_removes_every_factor_of_a_known_user(): void {
		( new UserFactors( 5 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );

		( new TwoFactorCommand() )->reset( array( 'alice' ), array( 'yes' => true ) );

		$this->assertFalse( ( new UserFactors( 5 ) )->has_any() );
		$this->assertNotEmpty( \WP_CLI::$successes );
	}

	public function test_reset_asks_for_confirmation_without_yes(): void {
		( new UserFactors( 5 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );

		try {
			( new TwoFactorCommand() )->reset( array( 'alice' ), array() );
			$this->fail( 'Expected a confirmation prompt.' );
		} catch ( \RuntimeException $e ) {
			$this->assertStringStartsWith( 'confirm:', $e->getMessage() );
		}

		$this->assertTrue( ( new UserFactors( 5 ) )->has_any() );
	}

	public function test_reset_resolves_a_numeric_id(): void {
		( new UserFactors( 5 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );

		( new TwoFactorCommand() )->reset( array( '5' ), array( 'yes' => true ) );

		$this->assertFalse( ( new UserFactors( 5 ) )->has_any() );
	}

	public function test_status_of_a_user_shows_counts_and_never_secrets(): void {
		( new UserFactors( 5 ) )->save_totp( 'JBSWY3DPEHPK3PXP' );
		( new UserFactors( 5 ) )->set_recovery( array( 'h1', 'h2', 'h3' ) );

		( new TwoFactorCommand() )->status( array( 'alice' ), array() );

		$dump = json_encode( array( $this->table, \WP_CLI::$log ) );
		$this->assertStringContainsString( '3', (string) $dump );
		$this->assertStringNotContainsString( 'JBSWY3DPEHPK3PXP', (string) $dump );
		$this->assertStringNotContainsString( 'h1', (string) $dump );
	}

	public function test_status_of_an_unknown_user_is_an_error(): void {
		$this->expectException( \RuntimeException::class );

		( new TwoFactorCommand() )->status( array( 'nobody' ), array() );
	}
}
