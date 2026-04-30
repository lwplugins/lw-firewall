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
			<?php esc_html_e( 'Core firewall settings — enable/disable, storage backend, rate limits and filter parameters.', 'lw-firewall' ); ?>
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
							'description' => __( 'Master switch — when off, the MU-plugin worker performs no checks (rate-limit, bot blocking, IP/geo blocking, auto-ban all skipped).', 'lw-firewall' ),
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
							'description' => __( 'Maximum number of rate-limited requests per IP within the time window. Applies to filter parameters, login, REST, XML-RPC and any other protected endpoint.', 'lw-firewall' ),
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
							'description' => __( 'Response when the rate limit is exceeded. 302 strips query parameters and redirects to the same path; 429 returns a Retry-After header.', 'lw-firewall' ),
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
							'description' => __( 'URL parameter substrings to rate-limit, one per line. Append |N for a stricter per-prefix limit (e.g. add-to-cart|10). Defaults: filter_|30, query_type_|30.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
		</table>
		<?php
	}
}
