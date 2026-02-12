<?php
/**
 * Protection Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

/**
 * Protection tab: endpoint toggles and auto-ban settings.
 */
final class TabProtection implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'protection';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Protection', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-lock';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		$this->render_endpoints();
		$this->render_auto_ban();
	}

	/**
	 * Render endpoint protection toggles.
	 */
	private function render_endpoints(): void {
		?>
		<h2><?php esc_html_e( 'Endpoint Protection', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'Enable rate limiting on specific WordPress endpoints.', 'lw-firewall' ); ?>
		</p>

		<table class="form-table">
			<?php
			$endpoints = [
				'protect_cron'     => [
					'label' => __( 'Rate-limit wp-cron.php requests', 'lw-firewall' ),
					'desc'  => __( 'Protects against DDoS attacks targeting wp-cron.php.', 'lw-firewall' ),
				],
				'protect_xmlrpc'   => [
					'label' => __( 'Rate-limit xmlrpc.php requests', 'lw-firewall' ),
					'desc'  => __( 'Protects against brute-force and DDoS via xmlrpc.php.', 'lw-firewall' ),
				],
				'protect_login'    => [
					'label' => __( 'Rate-limit wp-login.php requests', 'lw-firewall' ),
					'desc'  => __( 'Protects against brute-force login attempts.', 'lw-firewall' ),
				],
				'protect_rest_api' => [
					'label' => __( 'Rate-limit REST API requests', 'lw-firewall' ),
					'desc'  => __( 'Rate-limits /wp-json/ requests per IP.', 'lw-firewall' ),
				],
				'protect_404'      => [
					'label' => __( 'Block 404 flood', 'lw-firewall' ),
					'desc'  => __( 'Blocks IPs that generate excessive 404 errors (vulnerability scanning).', 'lw-firewall' ),
				],
			];

			foreach ( $endpoints as $name => $config ) :
				?>
				<tr>
					<th scope="row"><?php echo esc_html( $config['label'] ); ?></th>
					<td>
						<?php
						$this->render_checkbox_field(
							[
								'name'        => $name,
								'label'       => $config['label'],
								'description' => $config['desc'],
							]
						);
						?>
					</td>
				</tr>
			<?php endforeach; ?>
		</table>
		<?php
	}

	/**
	 * Render auto-ban settings.
	 */
	private function render_auto_ban(): void {
		?>
		<h2><?php esc_html_e( 'Auto-Ban', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'Automatically ban IPs that repeatedly exceed rate limits.', 'lw-firewall' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'Enable Auto-Ban', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_checkbox_field(
						[
							'name'        => 'auto_ban_enabled',
							'label'       => __( 'Ban IPs after repeated violations', 'lw-firewall' ),
							'description' => __( 'After the threshold is reached, the IP is banned for the configured duration.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Ban Threshold', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_number_field(
						[
							'name'        => 'auto_ban_threshold',
							'min'         => 2,
							'max'         => 100,
							'description' => __( 'Number of rate-limit violations before an IP is banned.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Ban Duration', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_number_field(
						[
							'name'        => 'auto_ban_duration',
							'min'         => 60,
							'max'         => 86400,
							'description' => __( 'How long the ban lasts in seconds (3600 = 1 hour).', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
		</table>
		<?php
	}
}
