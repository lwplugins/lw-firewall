<?php
/**
 * Side effects that follow every settings write.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings;

use LightweightPlugins\Firewall\Alerts\AdminBaseline;
use LightweightPlugins\Firewall\Geo\GeoActivation;
use LightweightPlugins\Firewall\Geo\HtaccessWriter;
use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * What the classic settings form did after saving, in the same order, now
 * shared by the REST save, the import and WP-CLI: seed the administrator
 * baseline when alerts were just switched on, resync the .htaccess geo block,
 * then bring the weekly CIDR refresh in step with the new settings.
 */
final class SaveEffects {

	/**
	 * Run the side effects.
	 *
	 * @param array<string, mixed> $before Stored settings before the write.
	 * @return void
	 */
	public static function apply( array $before ): void {
		$after = Options::get_stored();

		// Turning alerts on must not mail about the administrators the site
		// already had — snapshot them silently so only later arrivals alert.
		if ( self::needs_seed( $before, $after, AdminBaseline::is_seeded() ) ) {
			AdminBaseline::seed();
		}

		HtaccessWriter::sync();
		GeoActivation::sync_cron( Options::get_all() );
	}

	/**
	 * Whether the administrator baseline has to be seeded now.
	 *
	 * @param array<string, mixed> $before Stored settings before the write.
	 * @param array<string, mixed> $after  Stored settings after the write.
	 * @param bool                 $seeded Whether a baseline already exists.
	 * @return bool
	 */
	public static function needs_seed( array $before, array $after, bool $seeded ): bool {
		return ! $seeded && empty( $before['admin_alert_enabled'] ) && ! empty( $after['admin_alert_enabled'] );
	}
}
