<?php
/**
 * IP Rules Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rules\BanList;

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

		<?php $this->render_bans(); ?>
		<?php
	}

	/**
	 * Render the automatic-ban table with a per-row unblock button.
	 *
	 * This is the "a user says they are locked out" screen: it answers who is
	 * banned, why, and until when, and lets an administrator lift one without
	 * touching the storage backend by hand.
	 *
	 * @return void
	 */
	private function render_bans(): void {
		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		$rows    = BanList::all( $storage );
		?>
		<h2><?php esc_html_e( 'Automatic Bans', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'IP addresses banned automatically by the firewall — brute-force login lockouts, registration spam, password-reset floods and rate-limit escalation. Lifting a ban also clears the counters behind it, so the address starts from zero instead of being re-banned on its next request.', 'lw-firewall' ); ?>
		</p>

		<?php if ( empty( $rows ) ) : ?>
			<p><em><?php esc_html_e( 'No IP addresses are currently banned.', 'lw-firewall' ); ?></em></p>
			<?php
			return;
		endif;
		?>

		<table class="widefat striped" style="max-width: 900px;">
			<thead>
				<tr>
					<th><?php esc_html_e( 'IP address', 'lw-firewall' ); ?></th>
					<th><?php esc_html_e( 'Reason', 'lw-firewall' ); ?></th>
					<th><?php esc_html_e( 'Banned at', 'lw-firewall' ); ?></th>
					<th><?php esc_html_e( 'Expires', 'lw-firewall' ); ?></th>
					<th><?php esc_html_e( 'Action', 'lw-firewall' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $rows as $row ) : ?>
					<tr>
						<td><code><?php echo esc_html( $row['ip'] ); ?></code></td>
						<td>
							<?php echo esc_html( self::reason_label( $row['reason'] ) ); ?>
							<?php if ( ! $row['active'] ) : ?>
								<br /><span class="description"><?php esc_html_e( 'Tracked but no longer enforced — the storage backend was cleared.', 'lw-firewall' ); ?></span>
							<?php endif; ?>
						</td>
						<td><?php echo esc_html( $row['time'] > 0 ? wp_date( 'Y-m-d H:i:s', $row['time'] ) : '—' ); ?></td>
						<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', $row['expires'] ) ); ?></td>
						<td>
							<button type="submit" name="lw_firewall_unban" value="<?php echo esc_attr( $row['ip'] ); ?>" class="button button-small">
								<?php esc_html_e( 'Unblock', 'lw-firewall' ); ?>
							</button>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>

		<p>
			<button type="submit" name="lw_firewall_unban" value="__all__" class="button">
				<?php esc_html_e( 'Unblock all', 'lw-firewall' ); ?>
			</button>
		</p>
		<?php
	}

	/**
	 * Human label for a ban reason code.
	 *
	 * @param string $reason Reason code recorded with the ban.
	 * @return string
	 */
	private static function reason_label( string $reason ): string {
		$labels = [
			'login_lockout' => __( 'Too many failed logins', 'lw-firewall' ),
			'register_spam' => __( 'Registration spam', 'lw-firewall' ),
			'rate_limit'    => __( 'Rate limit exceeded', 'lw-firewall' ),
			'reset_ip'      => __( 'Password reset flood', 'lw-firewall' ),
			'reset_spam'    => __( 'Password reset bot request', 'lw-firewall' ),
		];

		return $labels[ $reason ] ?? ( '' !== $reason ? $reason : __( 'Unknown', 'lw-firewall' ) );
	}
}
