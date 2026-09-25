<?php
/**
 * Storage, geo and alert state for the Status screen.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Status;

use LightweightPlugins\Firewall\Alerts\AdminBaseline;
use LightweightPlugins\Firewall\Alerts\AdminDetector;
use LightweightPlugins\Firewall\Alerts\AdminMonitor;
use LightweightPlugins\Firewall\Alerts\AlertMailer;
use LightweightPlugins\Firewall\Alerts\AlertQueue;
use LightweightPlugins\Firewall\Geo\CidrUpdater;
use LightweightPlugins\Firewall\Geo\GeoActivation;
use LightweightPlugins\Firewall\Geo\HtaccessWriter;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageDetector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only facts about the subsystems around the request filter.
 */
final class EnvironmentState {

	/**
	 * Active storage backend, the probe and the file cache directory.
	 *
	 * @param array<string, mixed> $options Effective settings.
	 * @return array<string, mixed>
	 */
	public static function storage( array $options ): array {
		$preference = (string) ( $options['storage'] ?? 'auto' );
		$storage    = lw_firewall_resolve_storage( $preference );
		$dir        = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/cache/lw-firewall/' : '';

		return [
			'preference'        => $preference,
			'active'            => StorageDetector::detect( $preference ),
			'backend'           => self::backend_name( $storage ),
			'probe'             => StorageProbe::run( $storage ),
			'file_dir'          => $dir,
			'file_dir_writable' => '' !== $dir && wp_is_writable( is_dir( $dir ) ? $dir : dirname( $dir ) ),
		];
	}

	/**
	 * Geo blocking state: activation, cache freshness per country, .htaccess.
	 *
	 * @param array<string, mixed> $options Effective settings.
	 * @return array<string, mixed>
	 */
	public static function geo( array $options ): array {
		$countries = Options::sanitize_country_codes( (array) ( $options['blocked_countries'] ?? [] ) );
		$cache     = CidrUpdater::get_cache_dir();

		return [
			'enabled'            => ! empty( $options['geo_enabled'] ),
			'active'             => GeoActivation::is_active( $options ),
			'next_update'        => (int) wp_next_scheduled( CidrUpdater::CRON_HOOK ),
			'countries'          => array_map(
				static fn ( string $cc ): array => [
					'cc'    => $cc,
					'stale' => CidrUpdater::is_stale( $cc ),
				],
				$countries
			),
			'cache_dir'          => $cache,
			'cache_dir_writable' => wp_is_writable( is_dir( $cache ) ? $cache : dirname( $cache ) ),
			'htaccess_present'   => file_exists( ABSPATH . '.htaccess' ),
			'htaccess_rules'     => [] !== HtaccessWriter::rules_for( $options ),
		];
	}

	/**
	 * Administrator alert state (the Alerts tab's status block).
	 *
	 * @param array<string, mixed> $options Effective settings.
	 * @return array<string, mixed>
	 */
	public static function alerts( array $options ): array {
		$record = AdminBaseline::get_record();

		return [
			'enabled'        => ! empty( $options['admin_alert_enabled'] ),
			'admins_tracked' => null !== $record ? count( $record['ids'] ) : count( AdminDetector::current_admin_ids() ),
			'recipients'     => AlertMailer::recipients(),
			'snapshot_time'  => null !== $record ? $record['time'] : 0,
			'next_scan'      => AdminMonitor::next_scan(),
			'pending'        => AlertQueue::pending(),
			'mail_error'     => (bool) get_transient( AlertMailer::ERROR_TRANSIENT ),
		];
	}

	/**
	 * Short name of a storage instance.
	 *
	 * @param object $storage Storage backend.
	 * @return string apcu | redis | file | unknown.
	 */
	public static function backend_name( object $storage ): string {
		$map   = [
			'ApcuStorage'  => 'apcu',
			'RedisStorage' => 'redis',
			'FileStorage'  => 'file',
		];
		$parts = explode( '\\', get_class( $storage ) );

		return $map[ end( $parts ) ] ?? 'unknown';
	}
}
