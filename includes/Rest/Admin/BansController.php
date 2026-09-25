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
use LightweightPlugins\Firewall\Admin\Bans\SelfBanGuard;
use LightweightPlugins\Firewall\Admin\Bans\Unbanner;
use LightweightPlugins\Firewall\Admin\Bans\UserUnlocker;
use LightweightPlugins\Firewall\Admin\Status\EnvironmentState;
use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\IpSubject;
use LightweightPlugins\Firewall\OptionSchema;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rules\AutoBanner;
use LightweightPlugins\Firewall\Rules\BanList;
use LightweightPlugins\Firewall\Rules\IpMatcher;
use LightweightPlugins\Firewall\Rules\UserLockList;
use LightweightPlugins\Firewall\Rules\UserLockout;
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

		if ( SelfBanGuard::is_own_address( $ip, IpDetector::get_ip() ) ) {
			return Routes::error( 'lw_firewall_own_address', __( 'This is the address you are using right now. Banning it would lock you out of the whole site, the admin included.', 'lw-firewall' ), 409 );
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
	 * Lift the given bans and username locks, or all of them; one result per
	 * address and per username.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function unban( WP_REST_Request $request ) {
		$storage  = $this->storage();
		$unbanner = new Unbanner( new AutoBanner( $storage ) );
		$unlocker = new UserUnlocker( new UserLockout( $storage ) );
		$ips      = $request->get_param( 'ips' );
		$users    = $request->get_param( 'users' );
		$ips      = is_array( $ips ) ? array_values( $ips ) : [];
		$users    = is_array( $users ) ? array_values( $users ) : [];

		if ( true === rest_sanitize_boolean( $request->get_param( 'all' ) ) ) {
			$results      = $unbanner->lift_all();
			$user_results = $unlocker->unlock_all();
		} elseif ( [] !== $ips || [] !== $users ) {
			$results      = $unbanner->lift( $ips );
			$user_results = $unlocker->unlock( $users );
		} else {
			return Routes::error( 'lw_firewall_invalid', __( 'Send "ips" (addresses), "users" (username lock keys) or "all": true.', 'lw-firewall' ), 400 );
		}

		return new WP_REST_Response(
			[
				'results'      => $results,
				'user_results' => $user_results,
				'bans'         => $this->listing(),
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
				'store'      => [
					'preference' => $preference,
					'backend'    => EnvironmentState::backend_name( $storage ),
					'label'      => StorageDetector::detect( $preference ),
				],
				'reasons'    => $reasons,
				'user_locks' => UserLockList::all( $storage ),
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
