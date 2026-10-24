<?php
/**
 * Admin REST routes bootstrap.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers the lw-firewall/v1/admin/* routes used by the React admin.
 *
 * Every route requires manage_options; REST cookie auth supplies the nonce.
 * On multisite, the routes that write a resource every site shares (the ban
 * store, the MU-plugin worker, the geo data files) require
 * manage_network_options as well.
 */
final class Routes {

	/**
	 * REST namespace.
	 */
	public const NAMESPACE = 'lw-firewall/v1';

	/**
	 * Hook the route registration.
	 *
	 * @return void
	 */
	public function register(): void {
		add_action( 'rest_api_init', [ $this, 'register_routes' ] );
	}

	/**
	 * Register every admin route.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		( new SettingsController() )->register_routes();
		( new BansController() )->register_routes();
		( new LogsController() )->register_routes();
		( new MaintenanceController() )->register_routes();
		( new AlertsController() )->register_routes();
		( new TransferController() )->register_routes();
		( new StatusController() )->register_routes();
	}

	/**
	 * Permission callback shared by all admin routes.
	 *
	 * @return bool
	 */
	public static function can_manage(): bool {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Permission callback for routes that write a network-wide resource.
	 *
	 * @return bool
	 */
	public static function can_manage_network(): bool {
		if ( ! self::can_manage() ) {
			return false;
		}

		return ! is_multisite() || current_user_can( 'manage_network_options' );
	}

	/**
	 * Register one route with a handler per HTTP method.
	 *
	 * @param string                $path     Route path under the namespace.
	 * @param array<string, string> $handlers Method constant => public method name on $owner.
	 * @param object                $owner    Controller instance.
	 * @param array<int, string>    $network  Method constants that write a network-wide resource.
	 * @return void
	 */
	public static function add( string $path, array $handlers, object $owner, array $network = [] ): void {
		$endpoints = [];

		foreach ( $handlers as $methods => $callback ) {
			$endpoints[] = [
				'methods'             => $methods,
				'callback'            => [ $owner, $callback ],
				'permission_callback' => [ self::class, in_array( $methods, $network, true ) ? 'can_manage_network' : 'can_manage' ],
			];
		}

		register_rest_route( self::NAMESPACE, $path, $endpoints );
	}

	/**
	 * A translated REST error.
	 *
	 * @param string               $code    Error code.
	 * @param string               $message Translated message.
	 * @param int                  $status  HTTP status.
	 * @param array<string, mixed> $data    Extra error data.
	 * @return WP_Error
	 */
	public static function error( string $code, string $message, int $status, array $data = [] ): WP_Error {
		return new WP_Error( $code, $message, array_merge( [ 'status' => $status ], $data ) );
	}
}
