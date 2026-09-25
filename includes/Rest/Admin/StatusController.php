<?php
/**
 * Status REST controller.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use LightweightPlugins\Firewall\Admin\Status\StatusReport;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * GET /admin/status.
 */
final class StatusController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		Routes::add( '/admin/status', [ WP_REST_Server::READABLE => 'status' ], $this );
	}

	/**
	 * The full status report with warnings.
	 *
	 * @return WP_REST_Response
	 */
	public function status(): WP_REST_Response {
		return new WP_REST_Response( StatusReport::build() );
	}
}
