<?php
/**
 * LW Site Manager Integration.
 *
 * Registers Firewall abilities when LW Site Manager is active.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\SiteManager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks into LW Site Manager to register Firewall abilities.
 */
final class Integration {

	/**
	 * Initialize hooks. Safe to call even if Site Manager is not active.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'lw_site_manager_register_categories', [ self::class, 'register_category' ] );
		add_action( 'lw_site_manager_register_abilities', [ self::class, 'register_abilities' ] );
	}

	/**
	 * Register the Firewall ability category.
	 *
	 * @return void
	 */
	public static function register_category(): void {
		wp_register_ability_category(
			'firewall',
			[
				'label'       => __( 'Firewall', 'lw-firewall' ),
				'description' => __( 'Firewall management abilities: rate limiting, IP blocking, bot control and logs.', 'lw-firewall' ),
			]
		);
	}

	/**
	 * Register Firewall abilities.
	 *
	 * @param object $permissions Permission manager from Site Manager.
	 * @return void
	 */
	public static function register_abilities( object $permissions ): void {
		FirewallAbilities::register( $permissions );
	}
}
