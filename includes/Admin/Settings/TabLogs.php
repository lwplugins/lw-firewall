<?php
/**
 * Logs Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

use LightweightPlugins\Firewall\Logger;

/**
 * Logs tab: log toggle, log viewer table, clear button.
 */
final class TabLogs implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'logs';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Logs', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-list-view';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		?>
		<h2><?php esc_html_e( 'Request Logging', 'lw-firewall' ); ?></h2>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'Enable Logging', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_checkbox_field(
						[
							'name'        => 'log_enabled',
							'label'       => __( 'Log blocked requests', 'lw-firewall' ),
							'description' => __( 'Stores the last 100 blocked requests in the database.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
		</table>

		<?php $this->render_log_table(); ?>

		<p>
			<label>
				<input type="checkbox" name="lw_firewall_clear_log" value="1" />
				<?php esc_html_e( 'Clear all log entries on save', 'lw-firewall' ); ?>
			</label>
		</p>
		<?php
	}

	/**
	 * Render the log viewer table.
	 *
	 * @return void
	 */
	private function render_log_table(): void {
		$entries = Logger::get_entries();

		if ( empty( $entries ) ) {
			echo '<p class="description">' . esc_html__( 'No log entries yet.', 'lw-firewall' ) . '</p>';
			return;
		}

		?>
		<table class="widefat striped lw-firewall-log-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Time', 'lw-firewall' ); ?></th>
					<th><?php esc_html_e( 'IP', 'lw-firewall' ); ?></th>
					<th><?php esc_html_e( 'Reason', 'lw-firewall' ); ?></th>
					<th><?php esc_html_e( 'User-Agent', 'lw-firewall' ); ?></th>
					<th><?php esc_html_e( 'URL', 'lw-firewall' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $entries as $entry ) : ?>
					<tr>
						<td><?php echo esc_html( $entry['time'] ?? '' ); ?></td>
						<td><code><?php echo esc_html( $entry['ip'] ?? '' ); ?></code></td>
						<td><?php echo esc_html( $entry['reason'] ?? '' ); ?></td>
						<td class="lw-firewall-ua-cell"><?php echo esc_html( $entry['ua'] ?? '' ); ?></td>
						<td class="lw-firewall-url-cell"><?php echo esc_html( $entry['url'] ?? '' ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}
}
