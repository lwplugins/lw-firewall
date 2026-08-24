<?php
/**
 * Alerts Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

use LightweightPlugins\Firewall\Alerts\AdminBaseline;
use LightweightPlugins\Firewall\Alerts\AdminDetector;
use LightweightPlugins\Firewall\Alerts\AdminMonitor;
use LightweightPlugins\Firewall\Alerts\AlertMailer;
use LightweightPlugins\Firewall\Options;

/**
 * Alerts tab: email notification when an administrator account appears.
 */
final class TabAlerts implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'alerts';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Alerts', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-email-alt';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		?>
		<h2><?php esc_html_e( 'New Administrator Alert', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'Send an email whenever an account gains administrator privileges, or an existing administrator account is modified — no matter how it happened: the admin screens, a plugin, the REST API, WP-CLI, or a direct write into the database.', 'lw-firewall' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'Enable Alerts', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_checkbox_field(
						[
							'name'        => 'admin_alert_enabled',
							'label'       => __( 'Email me when a new administrator appears', 'lw-firewall' ),
							'description' => __( 'Works independently of the main firewall switch.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Notification Email', 'lw-firewall' ); ?></th>
				<td>
					<?php $this->render_email_field(); ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Account Takeover', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_checkbox_field(
						[
							'name'        => 'admin_alert_changes',
							'label'       => __( 'Also alert when an existing administrator is modified', 'lw-firewall' ),
							'description' => __( 'Watches the username, email address and password of every administrator. Rewriting an admin\'s email address is how an account is seized — it hands over the password reset flow while the user ID stays the same, so watching for new accounts alone would never see it.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Database Scan', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_checkbox_field(
						[
							'name'        => 'admin_alert_scan_enabled',
							'label'       => __( 'Hourly scan for administrators created outside WordPress', 'lw-firewall' ),
							'description' => __( 'Compares the live administrator list against a stored snapshot. This is what catches accounts inserted straight into the database, created by code that bypasses the WordPress user API, or added while this plugin was inactive.', 'lw-firewall' ),
						]
					);
					?>
					<p>
						<button type="submit" name="lw_firewall_save" value="admin_scan" class="button">
							<?php esc_html_e( 'Save &amp; run scan now', 'lw-firewall' ); ?>
						</button>
						<button type="submit" name="lw_firewall_save" value="admin_alert_test" class="button">
							<?php esc_html_e( 'Save &amp; send test email', 'lw-firewall' ); ?>
						</button>
					</p>
				</td>
			</tr>
		</table>

		<?php $this->render_status(); ?>

		<h2><?php esc_html_e( 'How detection works', 'lw-firewall' ); ?></h2>

		<table class="form-table lw-firewall-info-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'WordPress hooks', 'lw-firewall' ); ?></th>
				<td>
					<?php esc_html_e( 'Immediate. Catches every account creation or role change that goes through the WordPress user API — the Users screen, user registration, the REST API, WP-CLI, and any plugin or theme calling wp_insert_user() or set_role(). The alert names the acting user and their IP address.', 'lw-firewall' ); ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Database scan', 'lw-firewall' ); ?></th>
				<td>
					<?php esc_html_e( 'Within the hour. A snapshot of every administrator user ID is stored, and the scheduled scan diffs it against the live list. Anything that appears without a hook firing — a direct SQL INSERT, a modified wp_capabilities meta row, an account added while the plugin was off — shows up here and is flagged as created outside the normal WordPress flow.', 'lw-firewall' ); ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'What the snapshot stores', 'lw-firewall' ); ?></th>
				<td>
					<?php esc_html_e( 'Per administrator: the user ID, the username, the email address, and a digest of the stored password hash. The digest only ever answers "did this change?" — the password itself is never stored, never compared and never printed in an alert.', 'lw-firewall' ); ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'No duplicate alerts', 'lw-firewall' ); ?></th>
				<td>
					<?php esc_html_e( 'Both paths write to the same snapshot, so each event is reported exactly once. Existing administrators are recorded silently when the feature is turned on — you are only told about what happens afterwards. Removing an administrator is not reported; the account simply leaves the snapshot.', 'lw-firewall' ); ?>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Render the recipient email field.
	 *
	 * @return void
	 */
	private function render_email_field(): void {
		$value = (string) Options::get( 'admin_alert_email', '' );

		printf(
			'<input type="text" id="lw-fw-admin_alert_email" name="%s[admin_alert_email]" value="%s" class="regular-text" placeholder="%s" />',
			esc_attr( Options::OPTION_NAME . '_options' ),
			esc_attr( $value ),
			esc_attr( (string) get_option( 'admin_email', '' ) )
		);

		printf(
			'<p class="description">%s</p>',
			esc_html__( 'Separate multiple addresses with commas. Leave empty to use the site admin email.', 'lw-firewall' )
		);
	}

	/**
	 * Render current monitoring status.
	 *
	 * @return void
	 */
	private function render_status(): void {
		$snapshot  = AdminBaseline::last_updated();
		$next_scan = AdminMonitor::next_scan();
		$admins    = AdminBaseline::is_seeded() ? count( AdminBaseline::get_ids() ) : count( AdminDetector::current_admin_ids() );

		echo '<h2>' . esc_html__( 'Status', 'lw-firewall' ) . '</h2>';

		if ( get_transient( AlertMailer::ERROR_TRANSIENT ) ) {
			printf(
				'<div class="notice notice-warning inline"><p>%s</p></div>',
				esc_html__( 'The last alert email could not be sent. Check your site mail configuration (SMTP plugin, hosting mail limits) — an alert that never arrives is no alert at all.', 'lw-firewall' )
			);
		}

		echo '<table class="form-table lw-firewall-info-table">';

		printf(
			'<tr><th scope="row">%s</th><td>%s</td></tr>',
			esc_html__( 'Administrators tracked', 'lw-firewall' ),
			esc_html( (string) $admins )
		);

		printf(
			'<tr><th scope="row">%s</th><td>%s</td></tr>',
			esc_html__( 'Alerts go to', 'lw-firewall' ),
			esc_html( implode( ', ', AlertMailer::recipients() ) )
		);

		printf(
			'<tr><th scope="row">%s</th><td>%s</td></tr>',
			esc_html__( 'Snapshot taken', 'lw-firewall' ),
			esc_html( $snapshot > 0 ? wp_date( 'Y-m-d H:i:s', $snapshot ) : __( 'never — taken on the first scan', 'lw-firewall' ) )
		);

		printf(
			'<tr><th scope="row">%s</th><td>%s</td></tr>',
			esc_html__( 'Next scan', 'lw-firewall' ),
			esc_html( $next_scan > 0 ? wp_date( 'Y-m-d H:i:s', $next_scan ) : __( 'not scheduled', 'lw-firewall' ) )
		);

		echo '</table>';
	}
}
