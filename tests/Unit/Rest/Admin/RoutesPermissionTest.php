<?php
/**
 * Tests for the capability each admin route requires.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rest\Admin;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rest\Admin\Routes;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

require_once dirname( __DIR__, 2 ) . '/Support/WpRestServer.php';

/**
 * @covers \LightweightPlugins\Firewall\Rest\Admin\Routes
 */
final class RoutesPermissionTest extends MonkeyTestCase {

	/**
	 * Registers every admin route and returns the permission callback per
	 * "METHOD path".
	 *
	 * @return array<string, callable>
	 */
	private function permissions(): array {
		$found = [];

		Functions\when( 'register_rest_route' )->alias(
			static function ( string $ns, string $path, array $endpoints ) use ( &$found ): bool {
				foreach ( $endpoints as $endpoint ) {
					$found[ $endpoint['methods'] . ' ' . $path ] = $endpoint['permission_callback'];
				}
				return true;
			}
		);

		( new Routes() )->register_routes();

		return $found;
	}

	/**
	 * Stub a user holding only the given capabilities.
	 *
	 * @param array<int, string> $caps Capabilities.
	 * @return void
	 */
	private function user_with( array $caps ): void {
		Functions\when( 'current_user_can' )->alias(
			static fn ( string $cap ): bool => in_array( $cap, $caps, true )
		);
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function network_routes(): array {
		return [
			'ban'       => [ 'POST /admin/bans' ],
			'unban'     => [ 'POST /admin/bans/unban' ],
			'worker'    => [ 'POST /admin/worker/reinstall' ],
			'geo files' => [ 'POST /admin/geo/update' ],
		];
	}

	/**
	 * @dataProvider network_routes
	 */
	public function test_multisite_site_admin_is_refused_on_network_wide_writes( string $route ): void {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->user_with( [ 'manage_options' ] );

		$permissions = $this->permissions();

		$this->assertArrayHasKey( $route, $permissions );
		$this->assertFalse( call_user_func( $permissions[ $route ] ) );
	}

	/**
	 * @dataProvider network_routes
	 */
	public function test_multisite_network_admin_may_write( string $route ): void {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->user_with( [ 'manage_options', 'manage_network_options' ] );

		$this->assertTrue( call_user_func( $this->permissions()[ $route ] ) );
	}

	/**
	 * @dataProvider network_routes
	 */
	public function test_single_site_admin_may_write( string $route ): void {
		Functions\when( 'is_multisite' )->justReturn( false );
		$this->user_with( [ 'manage_options' ] );

		$this->assertTrue( call_user_func( $this->permissions()[ $route ] ) );
	}

	public function test_multisite_site_admin_keeps_read_access(): void {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->user_with( [ 'manage_options' ] );

		$permissions = $this->permissions();

		$this->assertTrue( call_user_func( $permissions['GET /admin/bans'] ) );
		$this->assertTrue( call_user_func( $permissions['GET /admin/settings'] ) );
		$this->assertTrue( call_user_func( $permissions['GET /admin/status'] ) );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function site_writes(): array {
		return [
			'settings' => [ 'POST /admin/settings' ],
			'import'   => [ 'POST /admin/import' ],
			'logs'     => [ 'DELETE /admin/logs' ],
		];
	}

	/**
	 * @dataProvider site_writes
	 */
	public function test_multisite_site_admin_keeps_per_site_writes( string $route ): void {
		Functions\when( 'is_multisite' )->justReturn( true );
		$this->user_with( [ 'manage_options' ] );

		$permissions = $this->permissions();

		$this->assertArrayHasKey( $route, $permissions );
		$this->assertTrue( call_user_func( $permissions[ $route ] ) );
	}

	public function test_users_without_manage_options_are_refused(): void {
		Functions\when( 'is_multisite' )->justReturn( false );
		$this->user_with( [] );

		foreach ( $this->permissions() as $route => $callback ) {
			$this->assertFalse( call_user_func( $callback ), $route );
		}
	}
}
