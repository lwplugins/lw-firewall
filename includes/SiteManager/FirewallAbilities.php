<?php
/**
 * Firewall Ability Definitions for LW Site Manager.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\SiteManager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers Firewall-specific abilities with the WordPress Abilities API.
 */
final class FirewallAbilities {

	/**
	 * Register all Firewall abilities.
	 *
	 * @param object $permissions Permission manager instance.
	 * @return void
	 */
	public static function register( object $permissions ): void {
		self::register_get_options( $permissions );
		self::register_get_log( $permissions );
		self::register_list_blocked( $permissions );
		self::register_block_ip( $permissions );
		self::register_unblock_ip( $permissions );
	}

	/**
	 * Register get-options ability.
	 *
	 * @param object $permissions Permission manager instance.
	 * @return void
	 */
	private static function register_get_options( object $permissions ): void {
		wp_register_ability(
			'lw-firewall/get-options',
			[
				'label'               => __( 'Get Firewall Options', 'lw-firewall' ),
				'description'         => __( 'Get all LW Firewall settings including rate limits, bot blocking and geo rules.', 'lw-firewall' ),
				'category'            => 'firewall',
				'execute_callback'    => [ FirewallService::class, 'get_options' ],
				'permission_callback' => $permissions->callback( 'can_manage_options' ),
				'input_schema'        => [
					'type'    => 'object',
					'default' => [],
				],
				'output_schema'       => [
					'type'       => 'object',
					'properties' => [
						'success' => [ 'type' => 'boolean' ],
						'options' => [ 'type' => 'object' ],
					],
				],
				'meta'                => self::readonly_meta(),
			]
		);
	}

	/**
	 * Register get-log ability.
	 *
	 * @param object $permissions Permission manager instance.
	 * @return void
	 */
	private static function register_get_log( object $permissions ): void {
		wp_register_ability(
			'lw-firewall/get-log',
			[
				'label'               => __( 'Get Firewall Log', 'lw-firewall' ),
				'description'         => __( 'Get recent firewall log entries (up to 100 blocked requests).', 'lw-firewall' ),
				'category'            => 'firewall',
				'execute_callback'    => [ FirewallService::class, 'get_log' ],
				'permission_callback' => $permissions->callback( 'can_manage_options' ),
				'input_schema'        => [
					'type'       => 'object',
					'properties' => [
						'limit' => [
							'type'        => 'integer',
							'description' => __( 'Number of log entries to return. Defaults to 25, max 100.', 'lw-firewall' ),
							'default'     => 25,
							'minimum'     => 1,
							'maximum'     => 100,
						],
					],
				],
				'output_schema'       => [
					'type'       => 'object',
					'properties' => [
						'success' => [ 'type' => 'boolean' ],
						'entries' => [
							'type'  => 'array',
							'items' => [ 'type' => 'object' ],
						],
						'total'   => [ 'type' => 'integer' ],
					],
				],
				'meta'                => self::readonly_meta(),
			]
		);
	}

	/**
	 * Register list-blocked ability.
	 *
	 * @param object $permissions Permission manager instance.
	 * @return void
	 */
	private static function register_list_blocked( object $permissions ): void {
		wp_register_ability(
			'lw-firewall/list-blocked',
			[
				'label'               => __( 'List Blocked IPs', 'lw-firewall' ),
				'description'         => __( 'List all manually blocked (blacklisted) IP addresses.', 'lw-firewall' ),
				'category'            => 'firewall',
				'execute_callback'    => [ FirewallService::class, 'list_blocked' ],
				'permission_callback' => $permissions->callback( 'can_manage_options' ),
				'input_schema'        => [
					'type'    => 'object',
					'default' => [],
				],
				'output_schema'       => [
					'type'       => 'object',
					'properties' => [
						'success' => [ 'type' => 'boolean' ],
						'ips'     => [
							'type'  => 'array',
							'items' => [ 'type' => 'string' ],
						],
						'total'   => [ 'type' => 'integer' ],
					],
				],
				'meta'                => self::readonly_meta(),
			]
		);
	}

	/**
	 * Register block-ip ability.
	 *
	 * @param object $permissions Permission manager instance.
	 * @return void
	 */
	private static function register_block_ip( object $permissions ): void {
		wp_register_ability(
			'lw-firewall/block-ip',
			[
				'label'               => __( 'Block IP Address', 'lw-firewall' ),
				'description'         => __( 'Add an IP address or CIDR range to the blacklist.', 'lw-firewall' ),
				'category'            => 'firewall',
				'execute_callback'    => [ FirewallService::class, 'block_ip' ],
				'permission_callback' => $permissions->callback( 'can_manage_options' ),
				'input_schema'        => [
					'type'       => 'object',
					'required'   => [ 'ip' ],
					'properties' => [
						'ip' => [
							'type'        => 'string',
							'description' => __( 'IP address or CIDR range to block (e.g. 1.2.3.4 or 10.0.0.0/8).', 'lw-firewall' ),
						],
					],
				],
				'output_schema'       => [
					'type'       => 'object',
					'properties' => [
						'success' => [ 'type' => 'boolean' ],
						'message' => [ 'type' => 'string' ],
					],
				],
				'meta'                => self::write_meta(),
			]
		);
	}

	/**
	 * Register unblock-ip ability.
	 *
	 * @param object $permissions Permission manager instance.
	 * @return void
	 */
	private static function register_unblock_ip( object $permissions ): void {
		wp_register_ability(
			'lw-firewall/unblock-ip',
			[
				'label'               => __( 'Unblock IP Address', 'lw-firewall' ),
				'description'         => __( 'Remove an IP address or CIDR range from the blacklist.', 'lw-firewall' ),
				'category'            => 'firewall',
				'execute_callback'    => [ FirewallService::class, 'unblock_ip' ],
				'permission_callback' => $permissions->callback( 'can_manage_options' ),
				'input_schema'        => [
					'type'       => 'object',
					'required'   => [ 'ip' ],
					'properties' => [
						'ip' => [
							'type'        => 'string',
							'description' => __( 'IP address or CIDR range to unblock.', 'lw-firewall' ),
						],
					],
				],
				'output_schema'       => [
					'type'       => 'object',
					'properties' => [
						'success' => [ 'type' => 'boolean' ],
						'message' => [ 'type' => 'string' ],
					],
				],
				'meta'                => self::write_meta(),
			]
		);
	}

	/**
	 * Read-only ability metadata.
	 *
	 * @return array<string, mixed>
	 */
	private static function readonly_meta(): array {
		return [
			'show_in_rest' => true,
			'annotations'  => [
				'readonly'    => true,
				'destructive' => false,
				'idempotent'  => true,
			],
		];
	}

	/**
	 * Write ability metadata.
	 *
	 * @return array<string, mixed>
	 */
	private static function write_meta(): array {
		return [
			'show_in_rest' => true,
			'annotations'  => [
				'readonly'    => false,
				'destructive' => false,
				'idempotent'  => true,
			],
		];
	}
}
