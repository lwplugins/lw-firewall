<?php
/**
 * Firewall Service for LW Site Manager abilities.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\SiteManager;

use LightweightPlugins\Firewall\Logger;
use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Executes Firewall abilities for the Site Manager.
 */
final class FirewallService {

	/**
	 * Get all LW Firewall options.
	 *
	 * @param array<string, mixed> $input Input parameters (unused).
	 * @return array<string, mixed>
	 */
	public static function get_options( array $input ): array { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Required by ability callback interface.
		return [
			'success' => true,
			'options' => Options::get_all(),
		];
	}

	/**
	 * Get recent firewall log entries.
	 *
	 * @param array<string, mixed> $input Input parameters.
	 * @return array<string, mixed>
	 */
	public static function get_log( array $input ): array {
		$limit   = isset( $input['limit'] ) ? (int) $input['limit'] : 25;
		$limit   = max( 1, min( 100, $limit ) );
		$entries = Logger::get_entries();
		$total   = count( $entries );

		return [
			'success' => true,
			'entries' => array_slice( $entries, 0, $limit ),
			'total'   => $total,
		];
	}

	/**
	 * List all manually blocked IP addresses.
	 *
	 * @param array<string, mixed> $input Input parameters (unused).
	 * @return array<string, mixed>
	 */
	public static function list_blocked( array $input ): array { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Required by ability callback interface.
		$ips = (array) Options::get( 'ip_blacklist', [] );

		return [
			'success' => true,
			'ips'     => array_values( $ips ),
			'total'   => count( $ips ),
		];
	}

	/**
	 * Add an IP address or CIDR range to the blacklist.
	 *
	 * @param array<string, mixed> $input Input parameters.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function block_ip( array $input ): array|\WP_Error {
		$ip = isset( $input['ip'] ) ? trim( (string) $input['ip'] ) : '';

		if ( '' === $ip ) {
			return new \WP_Error(
				'missing_ip',
				__( 'Provide an ip address or CIDR range.', 'lw-firewall' ),
				[ 'status' => 400 ]
			);
		}

		if ( ! self::is_valid_ip_or_cidr( $ip ) ) {
			return new \WP_Error(
				'invalid_ip',
				__( 'The provided value is not a valid IP address or CIDR range.', 'lw-firewall' ),
				[ 'status' => 400 ]
			);
		}

		$current = (array) Options::get( 'ip_blacklist', [] );

		if ( in_array( $ip, $current, true ) ) {
			return [
				'success' => true,
				'message' => sprintf(
					/* translators: %s: IP address */
					__( '%s is already on the blacklist.', 'lw-firewall' ),
					$ip
				),
			];
		}

		$current[]           = $ip;
		$all                 = Options::get_all();
		$all['ip_blacklist'] = $current;
		Options::save( $all );

		return [
			'success' => true,
			'message' => sprintf(
				/* translators: %s: IP address */
				__( '%s has been added to the blacklist.', 'lw-firewall' ),
				$ip
			),
		];
	}

	/**
	 * Remove an IP address or CIDR range from the blacklist.
	 *
	 * @param array<string, mixed> $input Input parameters.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function unblock_ip( array $input ): array|\WP_Error {
		$ip = isset( $input['ip'] ) ? trim( (string) $input['ip'] ) : '';

		if ( '' === $ip ) {
			return new \WP_Error(
				'missing_ip',
				__( 'Provide an ip address or CIDR range.', 'lw-firewall' ),
				[ 'status' => 400 ]
			);
		}

		$current = (array) Options::get( 'ip_blacklist', [] );
		$updated = array_values( array_filter( $current, static fn( $entry ) => $entry !== $ip ) );

		if ( count( $updated ) === count( $current ) ) {
			return new \WP_Error(
				'ip_not_found',
				sprintf(
					/* translators: %s: IP address */
					__( '%s was not found on the blacklist.', 'lw-firewall' ),
					$ip
				),
				[ 'status' => 404 ]
			);
		}

		$all                 = Options::get_all();
		$all['ip_blacklist'] = $updated;
		Options::save( $all );

		return [
			'success' => true,
			'message' => sprintf(
				/* translators: %s: IP address */
				__( '%s has been removed from the blacklist.', 'lw-firewall' ),
				$ip
			),
		];
	}

	/**
	 * Validate that a string is a valid IP address or CIDR range.
	 *
	 * @param string $value IP or CIDR to validate.
	 * @return bool
	 */
	private static function is_valid_ip_or_cidr( string $value ): bool {
		if ( str_contains( $value, '/' ) ) {
			[ $ip, $prefix ] = explode( '/', $value, 2 );

			if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return false;
			}

			$prefix = (int) $prefix;

			if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
				return $prefix >= 0 && $prefix <= 32;
			}

			return $prefix >= 0 && $prefix <= 128;
		}

		return (bool) filter_var( $value, FILTER_VALIDATE_IP );
	}
}
