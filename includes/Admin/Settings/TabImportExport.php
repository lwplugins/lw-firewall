<?php
/**
 * Import/Export Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

/**
 * Import/Export tab: export button + import file upload.
 */
final class TabImportExport implements TabInterface {

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'import-export';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Import / Export', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-download';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		$this->render_export_section();
		$this->render_import_section();
	}

	/**
	 * Render the export section.
	 *
	 * @return void
	 */
	private function render_export_section(): void {
		?>
		<h2><?php esc_html_e( 'Export Settings', 'lw-firewall' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Download your current firewall settings as a JSON file. You can use this file to import settings on another site.', 'lw-firewall' ); ?>
		</p>
		<p>
			<button type="submit" name="lw_firewall_export" value="1" class="button button-secondary">
				<?php esc_html_e( 'Export Settings', 'lw-firewall' ); ?>
			</button>
		</p>
		<?php
	}

	/**
	 * Render the import section.
	 *
	 * @return void
	 */
	private function render_import_section(): void {
		?>
		<hr />
		<h2><?php esc_html_e( 'Import Settings', 'lw-firewall' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Upload a previously exported JSON file to restore firewall settings. This will overwrite all current settings.', 'lw-firewall' ); ?>
		</p>

		<?php $this->render_import_notices(); ?>

		<table class="form-table">
			<tr>
				<th scope="row">
					<label for="lw-firewall-import-file"><?php esc_html_e( 'Settings File', 'lw-firewall' ); ?></label>
				</th>
				<td>
					<input type="file" id="lw-firewall-import-file" name="lw_firewall_import_file" accept=".json" />
				</td>
			</tr>
		</table>
		<p>
			<button type="submit" name="lw_firewall_import" value="1" class="button button-secondary">
				<?php esc_html_e( 'Import Settings', 'lw-firewall' ); ?>
			</button>
		</p>
		<?php
	}

	/**
	 * Render import-related admin notices.
	 *
	 * @return void
	 */
	private function render_import_notices(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		if ( isset( $_GET['imported'] ) && '1' === $_GET['imported'] ) {
			echo '<div class="notice notice-success inline"><p>';
			esc_html_e( 'Settings imported successfully.', 'lw-firewall' );
			echo '</p></div>';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		$error = isset( $_GET['import_error'] ) ? sanitize_key( $_GET['import_error'] ) : '';

		if ( $error ) {
			$messages = [
				'no_file'      => __( 'No file was uploaded.', 'lw-firewall' ),
				'read_failed'  => __( 'Could not read the uploaded file.', 'lw-firewall' ),
				'invalid_json' => __( 'The file does not contain valid JSON.', 'lw-firewall' ),
			];

			$message = $messages[ $error ] ?? __( 'Import failed.', 'lw-firewall' );

			echo '<div class="notice notice-error inline"><p>';
			echo esc_html( $message );
			echo '</p></div>';
		}
	}
}
