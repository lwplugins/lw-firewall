<?php
/**
 * Logs REST controller.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use LightweightPlugins\Firewall\Admin\Logs\LogQuery;
use LightweightPlugins\Firewall\Logger;
use LightweightPlugins\Firewall\Options;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * GET/DELETE /admin/logs.
 */
final class LogsController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		Routes::add(
			'/admin/logs',
			[
				WP_REST_Server::READABLE  => 'list_logs',
				WP_REST_Server::DELETABLE => 'clear_logs',
			],
			$this
		);
	}

	/**
	 * A filtered, paged slice of the log.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function list_logs( WP_REST_Request $request ): WP_REST_Response {
		$result = LogQuery::run(
			Logger::get_entries(),
			max( 1, absint( $request->get_param( 'page' ) ?? 1 ) ),
			absint( $request->get_param( 'per_page' ) ?? 20 ),
			sanitize_key( (string) $request->get_param( 'reason' ) ),
			sanitize_text_field( (string) $request->get_param( 'search' ) )
		);

		// An empty reason map must still be a JSON object.
		$result['reasons'] = (object) $result['reasons'];

		return new WP_REST_Response( array_merge( $result, [ 'enabled' => ! empty( Options::get( 'log_enabled' ) ) ] ) );
	}

	/**
	 * Delete every log entry.
	 *
	 * @return WP_REST_Response
	 */
	public function clear_logs(): WP_REST_Response {
		Logger::clear();

		return new WP_REST_Response(
			[
				'cleared' => true,
				'message' => __( 'All log entries were deleted.', 'lw-firewall' ),
			]
		);
	}
}
