<?php
/**
 * Settings REST controller.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use LightweightPlugins\Firewall\Settings\SettingsStore;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * GET/POST lw-firewall/v1/admin/settings.
 */
final class SettingsController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		Routes::add(
			'/admin/settings',
			[
				WP_REST_Server::READABLE  => 'get_settings',
				WP_REST_Server::CREATABLE => 'save_settings',
			],
			$this
		);
	}

	/**
	 * Current options plus the screen context.
	 *
	 * @return WP_REST_Response
	 */
	public function get_settings(): WP_REST_Response {
		return new WP_REST_Response( self::shape() );
	}

	/**
	 * Partial, atomic update: only the submitted keys change, and nothing is
	 * saved when any of them is invalid.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function save_settings( WP_REST_Request $request ) {
		$body = $request->get_json_params();

		if ( empty( $body ) ) {
			$body = $request->get_body_params();
		}

		$errors = SettingsStore::save( $body );

		if ( [] !== $errors ) {
			return Routes::error(
				'lw_firewall_invalid',
				__( 'Some settings are not valid. Nothing was saved.', 'lw-firewall' ),
				400,
				[ 'fields' => $errors ]
			);
		}

		return new WP_REST_Response( self::shape() );
	}

	/**
	 * Response shape shared by GET, POST and the import.
	 *
	 * @return array{options: array<string, mixed>, meta: array<string, mixed>}
	 */
	public static function shape(): array {
		return [
			'options' => SettingsStore::current(),
			'meta'    => SettingsMeta::build(),
		];
	}
}
