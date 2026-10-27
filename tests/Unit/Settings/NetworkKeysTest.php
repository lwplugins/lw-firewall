<?php
/**
 * Tests for the network-wide two-factor settings on multisite.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rest\Admin\SettingsController;
use LightweightPlugins\Firewall\Settings\NetworkKeys;
use LightweightPlugins\Firewall\Settings\SettingsTransfer;
use LightweightPlugins\Firewall\Settings\SettingsWriter;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\Tests\Unit\Support\WritePath;

require_once dirname( __DIR__ ) . '/Support/WpError.php';
require_once dirname( __DIR__ ) . '/Support/WpRestRequest.php';

/**
 * Main site = 1, holding twofa_enabled on and grace 3; the subsite has its own row.
 *
 * @covers \LightweightPlugins\Firewall\Settings\NetworkKeys
 * @covers \LightweightPlugins\Firewall\Options
 */
final class NetworkKeysTest extends MonkeyTestCase {

	/**
	 * Capabilities of the current user.
	 *
	 * @var array<int, string>
	 */
	private array $caps = array( 'manage_options' );

	private bool $main = true;

	private int $main_reads = 0;

	private OptionStore $store;

	protected function setUp(): void {
		parent::setUp();
		$this->store = WritePath::install(
			array(
				'twofa_enabled'    => false,
				'twofa_grace_days' => 7,
				'auto_ban_threshold'      => 9,
			)
		);
		Functions\when( 'current_user_can' )->alias( fn ( string $cap ): bool => in_array( $cap, $this->caps, true ) );
		Functions\when( 'is_main_site' )->alias( fn (): bool => $this->main );
		Functions\when( 'get_main_site_id' )->justReturn( 1 );
		Functions\when( 'get_blog_option' )->alias(
			function ( $id, $key, $fallback = false ) {
				++$this->main_reads;
				$this->assertSame( 1, $id );
				$this->assertSame( Options::OPTION_NAME, $key );

				return array(
					'twofa_enabled'        => true,
					'twofa_grace_days'     => 3,
					'twofa_required_roles' => array( 'administrator' ),
					'auto_ban_threshold'   => 2,
				);
			}
		);
	}

	private function multisite( bool $main ): void {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->main = $main;
		NetworkKeys::flush();
	}

	public function test_single_site_reads_its_own_values_and_can_edit(): void {
		$this->assertFalse( Options::get( 'twofa_enabled' ) );
		$this->assertSame( 7, Options::get( 'twofa_grace_days' ) );
		$this->assertTrue( NetworkKeys::editable() );
		$this->assertSame( array(), NetworkKeys::locked() );
		$this->assertSame( 0, $this->main_reads );
	}

	public function test_a_subsite_reads_the_two_factor_keys_from_the_main_site(): void {
		$this->multisite( false );

		$this->assertTrue( Options::get( 'twofa_enabled' ) );
		$this->assertSame( 3, Options::get( 'twofa_grace_days' ) );
		$this->assertSame( array( 'administrator' ), Options::get( 'twofa_required_roles' ) );
		$this->assertSame( 9, Options::get( 'auto_ban_threshold' ), 'Other settings stay per site.' );
		$this->assertTrue( Options::get_all()['twofa_enabled'] );
		$this->assertSame( 1, $this->main_reads, 'The main row is read once per request.' );
	}

	public function test_a_key_missing_on_the_main_site_takes_the_default(): void {
		$this->multisite( false );

		$this->assertTrue( Options::get( 'twofa_passkey_login' ) );
		$this->assertSame( 0, Options::get( 'twofa_remember_days' ) );
	}

	public function test_the_main_site_reads_its_own_row(): void {
		$this->multisite( true );

		$this->assertFalse( Options::get( 'twofa_enabled' ) );
		$this->assertSame( 0, $this->main_reads );
	}

	public function test_who_may_edit_on_multisite(): void {
		$this->multisite( false );
		$this->caps = array( 'manage_options', 'manage_network_options' );
		$this->assertFalse( NetworkKeys::editable(), 'Never on a subsite, not even a network admin.' );
		$this->assertContains( 'twofa_enabled', NetworkKeys::locked() );

		$this->multisite( true );
		$this->caps = array( 'manage_options' );
		$this->assertFalse( NetworkKeys::editable(), 'A main-site admin without the network capability.' );

		$this->caps = array( 'manage_options', 'manage_network_options' );
		$this->assertTrue( NetworkKeys::editable() );
	}

	public function test_every_two_factor_key_is_network_wide_and_nothing_else(): void {
		$keys = NetworkKeys::keys();

		$this->assertContains( 'twofa_enabled', $keys );
		$this->assertContains( 'twofa_block_app_passwords', $keys );
		$this->assertNotContains( 'auto_ban_threshold', $keys );
		foreach ( $keys as $key ) {
			$this->assertStringStartsWith( 'twofa_', $key );
		}
	}

	public function test_the_settings_rest_refuses_two_factor_keys_without_the_network_capability(): void {
		$this->multisite( true );

		$result = ( new SettingsController() )->save_settings( $this->request( array( 'twofa_enabled' => true ) ) );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'lw_firewall_network_setting', $result->get_error_code() );
		$this->assertSame( 403, $result->get_error_data()['status'] );
		$this->assertFalse( $this->store->data['lw_firewall']['twofa_enabled'], 'Nothing was saved.' );
	}

	public function test_the_settings_rest_refuses_two_factor_keys_on_a_subsite(): void {
		$this->multisite( false );
		$this->caps = array( 'manage_options', 'manage_network_options' );

		$result = ( new SettingsController() )->save_settings( $this->request( array( 'twofa_grace_days' => 1 ) ) );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'lw_firewall_network_setting', $result->get_error_code() );
	}

	public function test_refused_lists_only_locked_two_factor_keys(): void {
		$this->multisite( true );
		$this->assertSame( array( 'twofa_enabled' ), NetworkKeys::refused( array( 'twofa_enabled' => true, 'auto_ban_threshold' => 6 ) ) );

		$this->caps = array( 'manage_options', 'manage_network_options' );
		$this->assertSame( array(), NetworkKeys::refused( array( 'twofa_enabled' => true ) ) );
	}

	public function test_cli_and_import_skip_locked_two_factor_keys(): void {
		$this->multisite( false );

		$this->assertCount( 1, SettingsWriter::write_one( 'twofa_enabled', '1' ) );
		$report = SettingsTransfer::import( array( 'twofa_enabled' => true, 'auto_ban_threshold' => 6 ) );

		$this->assertContains( 'twofa_enabled', $report['locked'] );
		$this->assertSame( array( 'auto_ban_threshold' ), $report['imported'] );
		$this->assertFalse( $this->store->data['lw_firewall']['twofa_enabled'] );
	}

	/**
	 * A JSON request carrying the given body.
	 *
	 * @param array<string, mixed> $body Body.
	 */
	private function request( array $body ): \WP_REST_Request {
		return new class( $body ) extends \WP_REST_Request {
			/**
			 * @param array<string, mixed> $body Body.
			 */
			public function __construct( private array $body ) {
				parent::__construct();
			}

			public function get_body(): string {
				return (string) json_encode( $this->body );
			}

			/**
			 * @return array<string, mixed>
			 */
			public function get_json_params(): array {
				return $this->body;
			}
		};
	}
}
