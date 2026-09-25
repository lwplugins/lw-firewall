<?php
/**
 * Assembles the Status screen data.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Status;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Everything the classic Status tab showed, plus the client IP diagnostic,
 * the storage probe, geo and alert state, and the derived warnings.
 */
final class StatusReport {

	/**
	 * Build the report.
	 *
	 * @return array<string, mixed>
	 */
	public static function build(): array {
		$options = Options::get_all();

		$status = [
			'firewall'  => [
				'enabled'     => ! empty( $options['enabled'] ),
				'version'     => LW_FIREWALL_VERSION,
				'php_version' => PHP_VERSION,
				'wp_version'  => (string) get_bloginfo( 'version' ),
			],
			'worker'    => WorkerState::build(),
			'storage'   => EnvironmentState::storage( $options ),
			'client_ip' => ClientIpDiagnostic::build(),
			'geo'       => EnvironmentState::geo( $options ),
			'alerts'    => EnvironmentState::alerts( $options ),
		];

		$status['warnings'] = StatusWarnings::from( $status );

		return $status;
	}
}
