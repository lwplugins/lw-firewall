<?php
/**
 * Settings export and import.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings;

use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Settings\Input\OptionInput;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Export writes the stored settings (no wp-config.php pins) as JSON. Import
 * runs every value through the input layer: keys absent from the file keep
 * their current value, invalid keys are reported and skipped, pinned keys are
 * never written.
 */
final class SettingsTransfer {

	/**
	 * The stored settings as a downloadable JSON document.
	 *
	 * @return array{json: string, filename: string}
	 */
	public static function export(): array {
		return [
			'json'     => (string) wp_json_encode( Options::get_stored(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES ),
			'filename' => 'lw-firewall-settings-' . gmdate( 'Y-m-d' ) . '.json',
		];
	}

	/**
	 * Decode an export document into a key => value map.
	 *
	 * @param string $json Raw file contents.
	 * @return array<string, mixed>|null Null unless it is a JSON object holding at least one setting.
	 */
	public static function decode( string $json ): ?array {
		$data = json_decode( $json, true );

		// A JSON list has integer keys, so it holds no setting and fails here too.
		if ( ! is_array( $data ) || [] === array_intersect_key( $data, Options::get_defaults() ) ) {
			return null;
		}

		return $data;
	}

	/**
	 * Import decoded settings.
	 *
	 * @param array<string, mixed> $data Decoded document.
	 * @return array{imported: array<int, string>, invalid: array<string, array<int, string>>, locked: array<int, string>, unknown: array<int, string>}
	 */
	public static function import( array $data ): array {
		$report = OptionInput::parse( $data, Options::overridden() );

		if ( [] !== $report->values() ) {
			SettingsWriter::save( $report->values() );
		}

		return [
			'imported' => array_keys( $report->values() ),
			'invalid'  => $report->errors(),
			'locked'   => $report->locked(),
			'unknown'  => $report->unknown(),
		];
	}
}
