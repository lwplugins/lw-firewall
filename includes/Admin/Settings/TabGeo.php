<?php
/**
 * Geo Blocking Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

use LightweightPlugins\Firewall\Geo\CidrUpdater;

/**
 * Geo Blocking tab: country-based IP blocking.
 */
final class TabGeo implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'geo';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Geo Blocking', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-admin-site-alt3';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		?>
		<h2><?php esc_html_e( 'Geo Blocking', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'Block visitors from specific countries. Behind Cloudflare, the CF-IPCountry header is used (instant). Without Cloudflare, CIDR-based lookup is used (updated weekly).', 'lw-firewall' ); ?>
		</p>

		<table class="form-table">
			<?php $this->render_enable_row(); ?>
			<?php $this->render_action_row(); ?>
			<?php $this->render_countries_row(); ?>
		</table>

		<?php $this->render_update_button(); ?>
		<?php
	}

	/**
	 * Render enable checkbox row.
	 */
	private function render_enable_row(): void {
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Enable', 'lw-firewall' ); ?></th>
			<td>
				<?php
				$this->render_checkbox_field(
					[
						'name'  => 'geo_enabled',
						'label' => __( 'Enable Geo Blocking', 'lw-firewall' ),
					]
				);
				?>
			</td>
		</tr>
		<?php
	}

	/**
	 * Render block action select row.
	 */
	private function render_action_row(): void {
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Block Action', 'lw-firewall' ); ?></th>
			<td>
				<?php
				$this->render_select_field(
					[
						'name'    => 'geo_action',
						'label'   => '',
						'options' => [
							'403'      => __( '403 Forbidden', 'lw-firewall' ),
							'redirect' => __( 'Redirect to homepage', 'lw-firewall' ),
						],
					]
				);
				?>
			</td>
		</tr>
		<?php
	}

	/**
	 * Render blocked countries textarea row.
	 */
	private function render_countries_row(): void {
		?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Blocked Countries', 'lw-firewall' ); ?></th>
			<td>
				<?php
				$this->render_textarea_field(
					[
						'name'        => 'blocked_countries',
						'rows'        => 6,
						'description' => __( 'ISO 3166-1 alpha-2 country codes, one per line (e.g. IN, CN, RU).', 'lw-firewall' ),
					]
				);
				?>
			</td>
		</tr>
		<?php
	}

	/**
	 * Render manual CIDR update button.
	 */
	private function render_update_button(): void {
		$next_run = wp_next_scheduled( CidrUpdater::CRON_HOOK );
		?>
		<p style="margin-top: 1em;">
			<button type="submit" name="lw_firewall_geo_update" value="1" class="button button-secondary">
				<?php esc_html_e( 'Update CIDR Lists Now', 'lw-firewall' ); ?>
			</button>
			<?php if ( $next_run ) : ?>
				<span class="description" style="margin-left: 8px;">
					<?php
					/* translators: %s: human-readable time difference */
					printf( esc_html__( 'Next automatic update: %s', 'lw-firewall' ), esc_html( human_time_diff( $next_run ) ) );
					?>
				</span>
			<?php endif; ?>
		</p>
		<?php
	}
}
