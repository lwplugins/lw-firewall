<?php
/**
 * When geo blocking is in force, and keeping its weekly cron in step.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Geo;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One definition of "geo blocking is active", shared by the .htaccess rules
 * and the weekly CIDR refresh: the master switch, the geo switch and at least
 * one valid country. Anything less and neither the Apache block nor the
 * weekly download has a reason to exist.
 */
final class GeoActivation {

	public const SCHEDULE   = 'schedule';
	public const UNSCHEDULE = 'unschedule';
	public const KEEP       = '';

	/**
	 * Whether geo blocking is in force for the given effective settings.
	 *
	 * @param array<string, mixed> $options Effective settings (Options::get_all()).
	 * @return bool
	 */
	public static function is_active( array $options ): bool {
		return ! empty( $options['enabled'] )
			&& ! empty( $options['geo_enabled'] )
			&& [] !== Options::sanitize_country_codes( (array) ( $options['blocked_countries'] ?? [] ) );
	}

	/**
	 * What to do with the weekly refresh event.
	 *
	 * @param bool $active    Whether geo blocking is active.
	 * @param bool $scheduled Whether the event is currently scheduled.
	 * @return string One of the action constants.
	 */
	public static function cron_action( bool $active, bool $scheduled ): string {
		if ( $active && ! $scheduled ) {
			return self::SCHEDULE;
		}

		if ( ! $active && $scheduled ) {
			return self::UNSCHEDULE;
		}

		return self::KEEP;
	}

	/**
	 * Schedule or clear the weekly refresh to match the settings.
	 *
	 * @param array<string, mixed> $options Effective settings.
	 * @return void
	 */
	public static function sync_cron( array $options ): void {
		$action = self::cron_action( self::is_active( $options ), false !== wp_next_scheduled( CidrUpdater::CRON_HOOK ) );

		if ( self::SCHEDULE === $action ) {
			wp_schedule_event( time(), 'weekly', CidrUpdater::CRON_HOOK );
		} elseif ( self::UNSCHEDULE === $action ) {
			wp_clear_scheduled_hook( CidrUpdater::CRON_HOOK );
		}
	}
}
