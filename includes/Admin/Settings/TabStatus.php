<?php
/**
 * Status Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

use LightweightPlugins\Firewall\Activator;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageDetector;

/**
 * Status tab: worker status, storage info, reinstall button (read-only info).
 */
final class TabStatus implements TabInterface {

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'status';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Status', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-info';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		$worker_installed = Activator::is_worker_installed();
		$storage_pref     = (string) Options::get( 'storage', 'auto' );
		$active_storage   = StorageDetector::detect( $storage_pref );

		?>
		<h2><?php esc_html_e( 'Firewall Status', 'lw-firewall' ); ?></h2>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'MU-Plugin Worker', 'lw-firewall' ); ?></th>
				<td>
					<?php if ( $worker_installed ) : ?>
						<span style="color: #00a32a; font-weight: 600;">
							&#10003; <?php esc_html_e( 'Installed', 'lw-firewall' ); ?>
						</span>
					<?php else : ?>
						<span style="color: #d63638; font-weight: 600;">
							&#10007; <?php esc_html_e( 'Not installed', 'lw-firewall' ); ?>
						</span>
					<?php endif; ?>
					<p class="description">
						<?php esc_html_e( 'The MU-plugin worker intercepts requests early, before themes and plugins load.', 'lw-firewall' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Active Storage', 'lw-firewall' ); ?></th>
				<td>
					<strong><?php echo esc_html( $active_storage ); ?></strong>
					<p class="description">
						<?php esc_html_e( 'Storage backend used for rate-limit counters.', 'lw-firewall' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Reinstall Worker', 'lw-firewall' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="lw_firewall_reinstall_worker" value="1" />
						<?php esc_html_e( 'Reinstall MU-plugin worker on save', 'lw-firewall' ); ?>
					</label>
					<p class="description">
						<?php esc_html_e( 'Check this and save to reinstall the worker file.', 'lw-firewall' ); ?>
					</p>
				</td>
			</tr>
		</table>
		<?php
	}
}
