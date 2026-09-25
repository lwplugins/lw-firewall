<?php
/**
 * Worker and geo maintenance REST controller.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use LightweightPlugins\Firewall\Activator;
use LightweightPlugins\Firewall\Admin\Geo\GeoUpdateReport;
use LightweightPlugins\Firewall\Admin\Status\WorkerState;
use LightweightPlugins\Firewall\Admin\WorkerInstallReasons;
use LightweightPlugins\Firewall\Geo\CidrUpdater;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Settings\Input\CountryListParser;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * POST /admin/worker/reinstall and POST /admin/geo/update.
 */
final class MaintenanceController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		Routes::add( '/admin/worker/reinstall', [ WP_REST_Server::CREATABLE => 'reinstall_worker' ], $this );
		Routes::add( '/admin/geo/update', [ WP_REST_Server::CREATABLE => 'update_geo' ], $this );
	}

	/**
	 * Reinstall the MU-plugin worker and say what happened.
	 *
	 * @return WP_REST_Response
	 */
	public function reinstall_worker(): WP_REST_Response {
		$ok      = Activator::install_worker();
		$attempt = Activator::get_last_attempt();

		return new WP_REST_Response(
			[
				'ok'      => $ok,
				'message' => $ok
					? __( 'The worker was reinstalled. The version check updates on the next page load.', 'lw-firewall' )
					: WorkerInstallReasons::message( (string) ( $attempt['error'] ?? '' ) ),
				'worker'  => WorkerState::build(),
			]
		);
	}

	/**
	 * Download the CIDR lists now, for every blocked country or the given
	 * subset, and report each country and address family.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function update_geo( WP_REST_Request $request ) {
		$requested = $request->get_param( 'countries' );
		$countries = Options::sanitize_country_codes( (array) Options::get( 'blocked_countries', [] ) );

		if ( null !== $requested ) {
			$parsed = CountryListParser::parse( $requested );

			if ( ! $parsed->is_valid() ) {
				return Routes::error( 'lw_firewall_invalid', implode( ' ', $parsed->errors() ), 400, [ 'fields' => [ 'countries' => $parsed->errors() ] ] );
			}

			$countries = (array) $parsed->value();
		}

		if ( [] === $countries ) {
			return Routes::error( 'lw_firewall_geo_empty', __( 'There are no blocked countries to update.', 'lw-firewall' ), 400 );
		}

		$results = [];

		foreach ( $countries as $cc ) {
			$results[] = GeoUpdateReport::row( $cc, CidrUpdater::update_country_report( $cc ) );
		}

		$updated = count( array_filter( $results, static fn ( array $row ): bool => $row['v4'] || $row['v6'] ) );

		return new WP_REST_Response(
			[
				'results' => $results,
				'updated' => $updated,
				'failed'  => count( $results ) - $updated,
				/* translators: 1: countries updated, 2: countries requested */
				'message' => sprintf( __( '%1$d of %2$d countries updated.', 'lw-firewall' ), $updated, count( $results ) ),
			]
		);
	}
}
