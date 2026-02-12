<?php
/**
 * General Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

/**
 * General tab: enabled, storage, rate limit, time window, action, filter params.
 */
final class TabGeneral implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'general';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'General', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-shield';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		?>
		<h2><?php esc_html_e( 'General Settings', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'Configure firewall protection for WooCommerce filter requests.', 'lw-firewall' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'Enable Firewall', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_checkbox_field(
						[
							'name'        => 'enabled',
							'label'       => __( 'Enable firewall protection', 'lw-firewall' ),
							'description' => __( 'When enabled, filter requests are monitored for bots and rate-limited per IP.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Storage Backend', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_select_field(
						[
							'name'        => 'storage',
							'options'     => [
								'auto'  => __( 'Auto-detect', 'lw-firewall' ),
								'apcu'  => 'APCu',
								'redis' => 'Redis',
								'file'  => __( 'File', 'lw-firewall' ),
							],
							'description' => __( 'Storage backend for rate-limit counters. Auto-detect tries APCu, then Redis, then file.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Rate Limit', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_number_field(
						[
							'name'        => 'rate_limit',
							'min'         => 1,
							'max'         => 9999,
							'description' => __( 'Maximum number of filter requests per IP within the time window.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Time Window', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_number_field(
						[
							'name'        => 'rate_window',
							'min'         => 10,
							'max'         => 3600,
							'description' => __( 'Time window in seconds for rate limiting.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Rate Limit Action', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_select_field(
						[
							'name'        => 'action',
							'options'     => [
								'redirect' => __( '302 Redirect (strip filters)', 'lw-firewall' ),
								'429'      => __( '429 Too Many Requests', 'lw-firewall' ),
							],
							'description' => __( 'Action to take when rate limit is exceeded.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Filter Parameters', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_textarea_field(
						[
							'name'        => 'filter_params',
							'rows'        => 4,
							'description' => __( 'URL parameter prefixes to monitor (one per line). Default: filter_, query_type_', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
		</table>
		<?php
	}
}
