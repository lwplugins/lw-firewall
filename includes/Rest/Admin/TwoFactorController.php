<?php
/**
 * Two-factor REST controller.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use LightweightPlugins\Firewall\TwoFactor\Summary;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * GET /admin/2fa/summary.
 */
final class TwoFactorController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		Routes::add( '/admin/2fa/summary', [ WP_REST_Server::READABLE => 'summary' ], $this );
	}

	/**
	 * Users with a second factor per role (counts only).
	 *
	 * @return WP_REST_Response
	 */
	public function summary(): WP_REST_Response {
		return new WP_REST_Response( Summary::build() );
	}
}
