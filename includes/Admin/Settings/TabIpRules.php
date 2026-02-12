<?php
/**
 * IP Rules Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

/**
 * IP Rules tab: whitelist and blacklist.
 */
final class TabIpRules implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'ip-rules';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'IP Rules', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-networking';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		?>
		<h2><?php esc_html_e( 'IP Rules', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'Manually allow or block IP addresses. Supports individual IPs and CIDR ranges (e.g. 192.168.1.0/24).', 'lw-firewall' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'IP Whitelist', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_textarea_field(
						[
							'name'        => 'ip_whitelist',
							'rows'        => 6,
							'description' => __( 'IPs that are never rate-limited or blocked (one per line).', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'IP Blacklist', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_textarea_field(
						[
							'name'        => 'ip_blacklist',
							'rows'        => 6,
							'description' => __( 'IPs that are always blocked with 403 Forbidden (one per line).', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
		</table>
		<?php
	}
}
