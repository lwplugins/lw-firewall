<?php
/**
 * Security Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

/**
 * Security tab: HTTP security headers.
 */
final class TabSecurity implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'security';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Security', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-privacy';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		?>
		<h2><?php esc_html_e( 'Security Headers', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'Add security-related HTTP response headers to every page.', 'lw-firewall' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'Enable Security Headers', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_checkbox_field(
						[
							'name'        => 'security_headers',
							'label'       => __( 'Add security headers to all responses', 'lw-firewall' ),
							'description' => '',
						]
					);
					?>

					<div class="lw-firewall-section-description" style="margin-top: 15px;">
						<p><strong><?php esc_html_e( 'Headers added:', 'lw-firewall' ); ?></strong></p>
						<ul style="list-style: disc; margin-left: 20px;">
							<li><code>X-Content-Type-Options: nosniff</code></li>
							<li><code>X-Frame-Options: SAMEORIGIN</code></li>
							<li><code>Referrer-Policy: strict-origin-when-cross-origin</code></li>
							<li><code>Permissions-Policy: camera=(), microphone=(), geolocation=()</code></li>
							<li><code>X-XSS-Protection: 1; mode=block</code></li>
						</ul>
					</div>
				</td>
			</tr>
		</table>

		<h2><?php esc_html_e( 'What do these headers do?', 'lw-firewall' ); ?></h2>

		<table class="form-table lw-firewall-info-table">
			<tr>
				<th scope="row"><code>X-Content-Type-Options</code></th>
				<td>
					<?php esc_html_e( 'Prevents browsers from MIME-sniffing the content type. Without this, a browser might interpret a file differently than intended — for example, treating a text file as JavaScript — which can lead to XSS attacks.', 'lw-firewall' ); ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><code>X-Frame-Options</code></th>
				<td>
					<?php esc_html_e( 'Prevents your site from being embedded in an iframe on another domain. This protects against clickjacking attacks, where a malicious site overlays your page with invisible elements to trick users into clicking.', 'lw-firewall' ); ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><code>Referrer-Policy</code></th>
				<td>
					<?php esc_html_e( 'Controls how much referrer information is sent when navigating away from your site. The "strict-origin-when-cross-origin" value sends the full URL for same-origin requests but only the origin (domain) for cross-origin requests, preventing sensitive URL paths from leaking to third parties.', 'lw-firewall' ); ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><code>Permissions-Policy</code></th>
				<td>
					<?php esc_html_e( 'Disables browser features that your site does not use — camera, microphone, and geolocation. This prevents malicious scripts (e.g. from compromised third-party libraries) from silently accessing these sensitive APIs.', 'lw-firewall' ); ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><code>X-XSS-Protection</code></th>
				<td>
					<?php esc_html_e( 'Enables the built-in XSS filter in older browsers (IE, older Chrome). When a reflected XSS attack is detected, the browser blocks the page instead of rendering it. Modern browsers use Content-Security-Policy instead, but this header provides a safety net for legacy browsers.', 'lw-firewall' ); ?>
				</td>
			</tr>
		</table>
		<?php
	}
}
