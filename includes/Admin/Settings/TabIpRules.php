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
							'description' => __( 'IPs or CIDR ranges that bypass all firewall checks (one per line). Supports IPv4, IPv6, and CIDR notation (e.g. 10.0.0.0/8, 2001:db8::/32).', 'lw-firewall' ),
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
							'description' => __( 'IPs or CIDR ranges blocked with 403 Forbidden before any other check (one per line). Supports IPv4, IPv6, and CIDR notation.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
		</table>

		<h2><?php esc_html_e( 'Reverse Proxy', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'Leave this empty unless the site sits behind a proxy or load balancer. A forwarded-for header is written by the client until the hop that set it is known, so trusting one without listing the proxies would let any visitor choose their own IP — and with it their own rate-limit bucket, ban status and country. Cloudflare is handled automatically and needs nothing here.', 'lw-firewall' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'Trusted Proxies', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_textarea_field(
						[
							'name'        => 'trusted_proxies',
							'rows'        => 4,
							'description' => __( 'IPs or CIDR ranges of your own proxies, one per line. On the common "nginx in front of Apache on the same host" layout this is 127.0.0.1 — without it every visitor arrives as 127.0.0.1 and shares a single bucket.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Forwarded Header', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_select_field(
						[
							'name'    => 'proxy_header',
							'options' => [
								'x-forwarded-for' => 'X-Forwarded-For',
								'x-real-ip'       => 'X-Real-IP',
								'forwarded'       => 'Forwarded (RFC 7239)',
							],
						]
					);
					?>
					<p class="description"><?php esc_html_e( 'Read right to left, skipping hops that are themselves listed above. Only used when a trusted proxy is configured.', 'lw-firewall' ); ?></p>
				</td>
			</tr>
		</table>

		<?php BanTable::render(); ?>
		<?php
	}
}
