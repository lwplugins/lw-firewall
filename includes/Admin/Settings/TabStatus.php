<?php
/**
 * Status Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

use LightweightPlugins\Firewall\Activator;
use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\ProxyTrust;
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
	 * Warn when the address the firewall sees is not a real client address.
	 *
	 * Behind an unconfigured reverse proxy every request arrives as the proxy's
	 * own address, so the entire internet shares one rate-limit bucket, one ban
	 * and one country — and nothing else on this screen would say so. That was
	 * a silent, total bypass; now it is the first thing the tab reports.
	 *
	 * @return void
	 */
	private function render_client_ip_row(): void {
		$ip = IpDetector::get_ip();

		if ( ! ProxyTrust::is_non_routable( $ip ) ) {
			return;
		}

		printf(
			'<div class="notice notice-warning inline"><p><strong>%s</strong> %s</p><p><code>%s</code></p></div>',
			esc_html__( 'The firewall cannot see real visitor addresses.', 'lw-firewall' ),
			esc_html__( 'Every request reaches it as the address below, which is not routable on the internet — so all visitors share one rate-limit bucket, one ban and one country. If this site is behind a proxy or load balancer, list it under IP Rules → Reverse Proxy.', 'lw-firewall' ),
			esc_html( '' !== $ip ? $ip : '(none)' )
		);
	}

	/**
	 * Warn when the installed worker has never reported in.
	 *
	 * A matching version constant is not proof the worker runs: it defines the
	 * constant before it tries to load the plugin's classes, so a renamed or
	 * moved plugin directory produced a worker that looked healthy and did
	 * nothing at all.
	 *
	 * @return void
	 */
	private function render_worker_health_row(): void {
		if ( ! Activator::is_worker_installed() || Activator::worker_last_seen() > 0 ) {
			return;
		}

		printf(
			'<div class="notice notice-warning inline"><p><strong>%s</strong> %s</p></div>',
			esc_html__( 'The worker file is installed but has never reported in.', 'lw-firewall' ),
			esc_html__( 'It records a heartbeat the first time it runs. If this notice stays after a few page loads, the worker cannot load the plugin — most often because the plugin directory was renamed. Reinstall it below.', 'lw-firewall' )
		);
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		$worker_installed = Activator::is_worker_installed();
		$worker_version   = defined( 'LW_FIREWALL_WORKER_VERSION' ) ? LW_FIREWALL_WORKER_VERSION : '—';
		$plugin_version   = LW_FIREWALL_VERSION;
		$version_match    = $worker_version === $plugin_version;
		$mu_writable      = Activator::is_mu_dir_writable();
		$last_attempt     = Activator::get_last_attempt();
		$storage_pref     = (string) Options::get( 'storage', 'auto' );
		$active_storage   = StorageDetector::detect( $storage_pref );

		?>
		<h2><?php esc_html_e( 'Firewall Status', 'lw-firewall' ); ?></h2>

		<?php $this->render_client_ip_row(); ?>
		<?php $this->render_worker_health_row(); ?>

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
				<th scope="row"><?php esc_html_e( 'Worker Version', 'lw-firewall' ); ?></th>
				<td>
					<strong><?php echo esc_html( $worker_version ); ?></strong>
					<?php if ( $version_match ) : ?>
						<span style="color: #00a32a;">&#10003;</span>
					<?php else : ?>
						<span style="color: #d63638; font-weight: 600;">
							&#10007;
							<?php
							printf(
								/* translators: %s: expected plugin version */
								esc_html__( 'Mismatch — expected %s (will auto-update on next page load)', 'lw-firewall' ),
								esc_html( $plugin_version )
							);
							?>
						</span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'mu-plugins writable', 'lw-firewall' ); ?></th>
				<td>
					<?php if ( $mu_writable ) : ?>
						<span style="color: #00a32a; font-weight: 600;">&#10003; <?php esc_html_e( 'Yes', 'lw-firewall' ); ?></span>
					<?php else : ?>
						<span style="color: #d63638; font-weight: 600;">
							&#10007;
							<?php
							printf(
								/* translators: %s: mu-plugins directory path */
								esc_html__( 'No — make %s writable by the web server.', 'lw-firewall' ),
								'<code>' . esc_html( WPMU_PLUGIN_DIR ) . '</code>'
							);
							?>
						</span>
					<?php endif; ?>
				</td>
			</tr>
			<?php if ( null !== $last_attempt ) : ?>
				<tr>
					<th scope="row"><?php esc_html_e( 'Last install attempt', 'lw-firewall' ); ?></th>
					<td>
						<?php if ( $last_attempt['success'] ) : ?>
							<span style="color: #00a32a; font-weight: 600;">&#10003; <?php esc_html_e( 'Succeeded', 'lw-firewall' ); ?></span>
						<?php else : ?>
							<span style="color: #d63638; font-weight: 600;">
								&#10007;
								<?php echo esc_html( $last_attempt['error'] ); ?>
							</span>
						<?php endif; ?>
						<span style="color: #666;">
							(
							<?php
							printf(
								/* translators: %s: human-readable time difference */
								esc_html__( '%s ago', 'lw-firewall' ),
								esc_html( human_time_diff( (int) $last_attempt['time'] ) )
							);
							?>
							)
						</span>
					</td>
				</tr>
			<?php endif; ?>
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
