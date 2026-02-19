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

		Options::save( $sanitized );

		\LightweightPlugins\Firewall\Geo\HtaccessWriter::sync();

		self::redirect( 'imported', '1' );
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
