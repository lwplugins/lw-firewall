<?php
/**
 * The meta block of the settings response.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rest\Admin;

use LightweightPlugins\Firewall\Data\Countries;
use LightweightPlugins\Firewall\Geo\CidrUpdater;
use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\OptionSchema;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rules\SecurityHeaders;
use LightweightPlugins\Firewall\Settings\SettingsStore;
use LightweightPlugins\Firewall\Storage\ApcuStorage;
use LightweightPlugins\Firewall\Storage\RedisStorage;
use LightweightPlugins\Firewall\Storage\StorageDetector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Choices, limits and environment facts the settings UI needs but never
 * writes.
 */
final class SettingsMeta {

	/**
	 * Documentation URL.
	 */
	public const DOCS_URL = 'https://lwplugins.com/docs/lw-firewall/';

	/**
	 * Build the meta block.
	 *
	 * @return array<string, mixed>
	 */
	public static function build(): array {
		$defaults = Options::get_defaults();
		$locked   = Options::overridden();

		return [
			'locked'                 => $locked,
			'locked_constants'       => (object) array_combine(
				$locked,
				array_map( static fn ( string $key ): string => Options::CONST_PREFIX . strtoupper( $key ), $locked )
			),
			'defaults'               => SettingsStore::typed( $defaults, $defaults ),
			'ranges'                 => (object) self::ranges(),
			'enums'                  => (object) OptionSchema::enums(),
			'storage_backends'       => self::storage_backends(),
			'countries'              => (object) Countries::all(),
			'bots_defaults'          => $defaults['blocked_bots'],
			'filter_params_defaults' => $defaults['filter_params'],
			'server'                 => self::server(),
			'docs_url'               => self::DOCS_URL,
		];
	}

	/**
	 * Numeric bounds as {min, max}: the UI uses exactly the server's range.
	 *
	 * @return array<string, array{min: int, max: int}>
	 */
	private static function ranges(): array {
		$ranges = [];

		foreach ( OptionSchema::ranges() as $key => $range ) {
			$ranges[ $key ] = [
				'min' => $range[0],
				'max' => $range[1],
			];
		}

		return $ranges;
	}

	/**
	 * Storage choices and whether this PHP process can use them.
	 *
	 * @return array<int, array{value: string, label: string, available: bool}>
	 */
	private static function storage_backends(): array {
		return [
			[
				'value'     => 'auto',
				'label'     => __( 'Auto-detect', 'lw-firewall' ),
				'available' => true,
			],
			[
				'value'     => 'apcu',
				'label'     => 'APCu',
				'available' => ApcuStorage::is_available(),
			],
			[
				'value'     => 'redis',
				'label'     => 'Redis',
				'available' => RedisStorage::is_available(),
			],
			[
				'value'     => 'file',
				'label'     => __( 'File', 'lw-firewall' ),
				'available' => true,
			],
		];
	}

	/**
	 * Environment facts shown next to fields.
	 *
	 * @return array<string, mixed>
	 */
	private static function server(): array {
		$headers = [];

		foreach ( SecurityHeaders::HEADERS as $name => $value ) {
			$headers[] = [
				'name'  => $name,
				'value' => $value,
			];
		}

		return [
			'admin_email'        => (string) get_option( 'admin_email', '' ),
			'users_can_register' => (bool) get_option( 'users_can_register' ),
			'mu_plugins_dir'     => defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '',
			'security_headers'   => $headers,
			'geo_next_update'    => (int) wp_next_scheduled( CidrUpdater::CRON_HOOK ),
			'cloudflare'         => IpDetector::is_cloudflare_request(),
			'storage_active'     => StorageDetector::detect( (string) Options::get( 'storage', 'auto' ) ),
		];
	}
}
