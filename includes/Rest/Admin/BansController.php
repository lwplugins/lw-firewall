<?php
/**
 * Bans REST controller.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use LightweightPlugins\Firewall\Admin\Bans\BanReasons;
use LightweightPlugins\Firewall\Admin\Bans\BanRows;
use LightweightPlugins\Firewall\Admin\Bans\Unbanner;
use LightweightPlugins\Firewall\Admin\Status\EnvironmentState;
use LightweightPlugins\Firewall\IpSubject;
use LightweightPlugins\Firewall\OptionSchema;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rules\AutoBanner;
use LightweightPlugins\Firewall\Rules\BanList;
use LightweightPlugins\Firewall\Rules\IpMatcher;
use LightweightPlugins\Firewall\Settings\Input\IntParser;
use LightweightPlugins\Firewall\Storage\StorageDetector;
use LightweightPlugins\Firewall\Storage\StorageInterface;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * GET/POST /admin/bans and POST /admin/bans/unban.
 */
final class BansController {

	/**
	 * Register the routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		Routes::add(
			'/admin/bans',
			[
				WP_REST_Server::READABLE  => 'list_bans',
				WP_REST_Server::CREATABLE => 'add_ban',
			],
			$this
		);
		Routes::add( '/admin/bans/unban', [ WP_REST_Server::CREATABLE => 'unban' ], $this );
	}

	/**
	 * Every tracked ban, reconciled against the active storage.
	 *
	 * @return WP_REST_Response
	 */
	public function list_bans(): WP_REST_Response {
		return new WP_REST_Response( $this->listing() );
	}

	/**
	 * Ban one address for a while (reason "manual").
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function add_ban( WP_REST_Request $request ) {
		$ip = trim( (string) $request->get_param( 'ip' ) );

		if ( '' === IpSubject::parse( $ip ) ) {
			return Routes::error( 'lw_firewall_invalid_ip', __( 'That is not a valid IP address.', 'lw-firewall' ), 400 );
		}

		[ $min, $max ] = OptionSchema::ranges()['auto_ban_duration'];
		$duration      = IntParser::parse( $request->get_param( 'duration' ) ?? Options::get( 'auto_ban_duration', 3600 ), $min, $max );

		if ( ! $duration->is_valid() ) {
			return Routes::error( 'lw_firewall_invalid', implode( ' ', $duration->errors() ), 400, [ 'fields' => [ 'duration' => $duration->errors() ] ] );
		}

		if ( filter_var( $ip, FILTER_VALIDATE_IP ) && IpMatcher::matches( $ip, array_map( 'strval', (array) Options::get( 'ip_whitelist', [] ) ) ) ) {
			return Routes::error( 'lw_firewall_whitelisted', __( 'This address is on the IP whitelist, which bypasses every check — a ban would have no effect. Remove it from the whitelist first.', 'lw-firewall' ), 409 );
		}

		$banner = new AutoBanner( $this->storage() );
		$banner->ban( $ip, (int) $duration->value(), 'manual' );

		if ( ! $banner->is_banned( $ip ) ) {
			return Routes::error( 'lw_firewall_ban_failed', __( 'This address cannot be banned: it is private, shared or a trusted proxy (banning it would lock out every visitor behind it), or the storage backend refused the write.', 'lw-firewall' ), 409 );
		}

		return new WP_REST_Response(
			[
				'ok'      => true,
				'ip'      => IpSubject::of( $ip ),
				'message' => __( 'Address banned.', 'lw-firewall' ),
				'bans'    => $this->listing(),
			]
		);
	}

	/**
	 * Lift the given bans, or all of them; one result per address.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function unban( WP_REST_Request $request ) {
		$unbanner = new Unbanner( new AutoBanner( $this->storage() ) );
		$ips      = $request->get_param( 'ips' );

		if ( true === rest_sanitize_boolean( $request->get_param( 'all' ) ) ) {
			$results = $unbanner->lift_all();
		} elseif ( is_array( $ips ) && [] !== $ips ) {
			$results = $unbanner->lift( array_values( $ips ) );
		} else {
			return Routes::error( 'lw_firewall_invalid', __( 'Send "ips" (a list of addresses) or "all": true.', 'lw-firewall' ), 400 );
		}

		return new WP_REST_Response(
			[
				'results' => $results,
				'bans'    => $this->listing(),
			]
		);
	}

	/**
	 * The listing shape shared by every route.
	 *
	 * @return array<string, mixed>
	 */
	private function listing(): array {
		$preference = (string) Options::get( 'storage', 'auto' );
		$storage    = $this->storage();
		$reasons    = [];

		foreach ( array_keys( BanReasons::all() ) as $code ) {
			$reasons[ $code ] = [
				'label' => BanReasons::label( $code ),
				'hint'  => BanReasons::hint( $code ),
			];
		}

		return array_merge(
			BanRows::build( BanList::all( $storage ), time() ),
			[
				'store'   => [
					'preference' => $preference,
					'backend'    => EnvironmentState::backend_name( $storage ),
					'label'      => StorageDetector::detect( $preference ),
				],
				'reasons' => $reasons,
			]
		);
	}

	/**
	 * The storage the bans live in.
	 *
	 * @return StorageInterface
	 */
	private function storage(): StorageInterface {
		return lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
	}
}
