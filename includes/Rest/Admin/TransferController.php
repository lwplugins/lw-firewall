<?php
/**
 * Settings import/export REST controller.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use LightweightPlugins\Firewall\Settings\SettingsTransfer;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * GET /admin/export and POST /admin/import.
 */
final class TransferController {

	/**
	 * Largest accepted import document, in bytes. An export is a few KB.
	 */
	private const MAX_BYTES = 262144;

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		Routes::add( '/admin/export', [ WP_REST_Server::READABLE => 'export' ], $this );
		Routes::add( '/admin/import', [ WP_REST_Server::CREATABLE => 'import' ], $this );
	}

	/**
	 * The stored settings as a JSON document (no wp-config.php pins).
	 *
	 * @return WP_REST_Response
	 */
	public function export(): WP_REST_Response {
		return new WP_REST_Response( SettingsTransfer::export() );
	}

	/**
	 * Import an export document through the settings input layer.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function import( WP_REST_Request $request ) {
		$json = $request->get_param( 'json' );

		if ( ! is_string( $json ) || strlen( $json ) > self::MAX_BYTES ) {
			return Routes::error( 'lw_firewall_import_invalid', __( 'Send the exported file contents as "json" (at most 256 KB).', 'lw-firewall' ), 400 );
		}

		$data = SettingsTransfer::decode( $json );

		if ( null === $data ) {
			return Routes::error( 'lw_firewall_import_invalid', __( 'The file is not an LW Firewall settings export: it is not valid JSON, or it holds no known setting.', 'lw-firewall' ), 400 );
		}

		$report = SettingsTransfer::import( $data );

		// An empty per-key error map must still be a JSON object.
		$report['invalid'] = (object) $report['invalid'];

		return new WP_REST_Response( array_merge( SettingsController::shape(), [ 'report' => $report ] ) );
	}
}
