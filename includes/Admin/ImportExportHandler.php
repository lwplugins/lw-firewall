<?php
/**
 * Import/Export Handler class.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin;

use LightweightPlugins\Firewall\Options;

/**
 * Handles settings export (JSON download) and import (JSON upload).
 */
final class ImportExportHandler {

	/**
	 * Handle export or import if requested.
	 *
	 * @return void
	 */
	public static function maybe_handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( ! isset( $_POST['_lw_firewall_nonce'] )
			|| ! wp_verify_nonce( sanitize_key( $_POST['_lw_firewall_nonce'] ), 'lw_firewall_save' )
		) {
			return;
		}

		if ( isset( $_POST['lw_firewall_export'] ) ) {
			self::handle_export();
		}

		if ( isset( $_POST['lw_firewall_import'] ) ) {
			self::handle_import();
		}
	}

	/**
	 * Export settings as JSON file download.
	 *
	 * @return void
	 */
	private static function handle_export(): void {
		$options = Options::get_all();
		$json    = wp_json_encode( $options, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );

		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=lw-firewall-settings.json' );
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );

		echo $json; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON file download.
		exit;
	}

	/**
	 * Import settings from uploaded JSON file.
	 *
	 * @return void
	 */
	private static function handle_import(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_handle().
		if ( empty( $_FILES['lw_firewall_import_file']['tmp_name'] ) ) {
			self::redirect( 'import_error', 'no_file' );
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_handle().
		$tmp_file = sanitize_text_field( $_FILES['lw_firewall_import_file']['tmp_name'] );
		$contents = file_get_contents( $tmp_file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading uploaded temp file.

		if ( false === $contents ) {
			self::redirect( 'import_error', 'read_failed' );
			return;
		}

		$data = json_decode( $contents, true );

		if ( ! is_array( $data ) ) {
			self::redirect( 'import_error', 'invalid_json' );
			return;
		}

		$defaults  = Options::get_defaults();
		$sanitized = [];

		foreach ( $defaults as $key => $default_value ) {
			$sanitized[ $key ] = array_key_exists( $key, $data ) ? $data[ $key ] : $default_value;
		}

		Options::save( self::sanitize_lists( $sanitized ) );

		\LightweightPlugins\Firewall\Geo\HtaccessWriter::sync();

		self::redirect( 'imported', '1' );
	}

	/**
	 * Sanitize list-type option values coming from an untrusted import file.
	 *
	 * The form-save path validates these via InputParserTrait, but the import
	 * path previously copied raw JSON values straight into Options::save(). This
	 * strips empty entries (a blank blocked_bots entry would 403 every request)
	 * and reduces blocked_countries to valid codes (which reach include()/
	 * .htaccess/cache-file sinks).
	 *
	 * @param array<string, mixed> $values Merged option values.
	 * @return array<string, mixed>
	 */
	private static function sanitize_lists( array $values ): array {
		foreach ( [ 'blocked_bots', 'ip_whitelist', 'ip_blacklist', 'filter_params' ] as $key ) {
			$values[ $key ] = self::clean_list( $values[ $key ] ?? [] );
		}

		$values['blocked_countries'] = Options::sanitize_country_codes(
			(array) ( $values['blocked_countries'] ?? [] )
		);

		return $values;
	}

	/**
	 * Coerce a raw imported value into an array of non-empty, sanitized strings.
	 *
	 * @param mixed $value Raw value (array, or newline/comma string).
	 * @return array<int, string>
	 */
	private static function clean_list( mixed $value ): array {
		if ( ! is_array( $value ) ) {
			$value = is_string( $value ) ? (array) preg_split( '/[\r\n,]+/', $value ) : [];
		}

		$value = array_map( static fn ( $entry ): string => sanitize_text_field( (string) $entry ), $value );
		$value = array_filter( array_map( 'trim', $value ), static fn ( string $entry ): bool => '' !== $entry );

		return array_values( $value );
	}

	/**
	 * Redirect back to the settings page.
	 *
	 * @param string $param Query parameter name.
	 * @param string $value Query parameter value.
	 * @return void
	 */
	private static function redirect( string $param, string $value ): void {
		wp_safe_redirect(
			add_query_arg(
				[
					'page' => SettingsPage::SLUG,
					$param => $value,
				],
				admin_url( 'admin.php' )
			) . '#import-export'
		);
		exit;
	}
}
