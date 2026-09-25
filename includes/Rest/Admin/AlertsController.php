<?php
/**
 * Administrator alert actions REST controller.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use LightweightPlugins\Firewall\Admin\Alerts\AlertOutcome;
use LightweightPlugins\Firewall\Admin\Status\EnvironmentState;
use LightweightPlugins\Firewall\Alerts\AdminMonitor;
use LightweightPlugins\Firewall\Alerts\AlertMailer;
use LightweightPlugins\Firewall\Options;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * POST /admin/alerts/scan and POST /admin/alerts/test. Neither saves the
 * form: they act on the stored settings.
 */
final class AlertsController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		Routes::add( '/admin/alerts/scan', [ WP_REST_Server::CREATABLE => 'scan' ], $this );
		Routes::add( '/admin/alerts/test', [ WP_REST_Server::CREATABLE => 'test' ], $this );
	}

	/**
	 * Run the administrator scan now.
	 *
	 * @return WP_REST_Response
	 */
	public function scan(): WP_REST_Response {
		$outcome = AlertOutcome::scan( AdminMonitor::run_scan() );

		return new WP_REST_Response( array_merge( $outcome, [ 'alerts' => EnvironmentState::alerts( Options::get_all() ) ] ) );
	}

	/**
	 * Send a test alert to the configured recipients.
	 *
	 * @return WP_REST_Response
	 */
	public function test(): WP_REST_Response {
		$recipients = AlertMailer::recipients();
		$sent       = [] !== $recipients && AlertMailer::send_test();

		return new WP_REST_Response( array_merge( AlertOutcome::test( [] !== $recipients, $sent ), [ 'recipients' => $recipients ] ) );
	}
}
