<?php
/**
 * Stubs for code that goes through SettingsWriter.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Support;

use Brain\Monkey\Functions;

/**
 * Installs the in-memory option store plus the handful of WordPress calls the
 * post-save side effects reach (translations, is_email, the geo cron). There
 * is no .htaccess next to the test ABSPATH, so the geo sync is a no-op.
 */
final class WritePath {

	/**
	 * Install the stubs.
	 *
	 * @param array<string, mixed> $settings Initial stored settings (lw_firewall option).
	 * @return OptionStore
	 */
	public static function install( array $settings = array() ): OptionStore {
		Functions\stubTranslationFunctions();
		Functions\when( 'is_email' )->alias(
			static fn ( string $email ) => false !== filter_var( $email, FILTER_VALIDATE_EMAIL ) ? $email : false
		);
		Functions\when( 'wp_next_scheduled' )->justReturn( false );
		Functions\when( 'wp_schedule_event' )->justReturn( true );
		Functions\when( 'wp_clear_scheduled_hook' )->justReturn( 0 );

		// A seeded baseline keeps the alert side effect out of the way.
		return OptionStore::install(
			array(
				'lw_firewall'                => $settings,
				'lw_firewall_admin_baseline' => array(
					'ids'  => array( 1 ),
					'time' => 1,
				),
			)
		);
	}
}
