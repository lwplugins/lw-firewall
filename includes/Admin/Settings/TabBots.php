<?php
/**
 * Blocked Bots Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

/**
 * Bots tab: blocked User-Agent strings textarea.
 */
final class TabBots implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'bots';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Blocked Bots', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-dismiss';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		?>
		<h2><?php esc_html_e( 'Blocked Bots', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'User-Agent strings to block (one per line, case-insensitive substring match).', 'lw-firewall' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'Blocked User-Agents', 'lw-firewall' ); ?></th>
				<td>
					<?php
					$this->render_textarea_field(
						[
							'name'        => 'blocked_bots',
							'rows'        => 12,
							'description' => __( 'Requests matching these strings are immediately blocked with 403.', 'lw-firewall' ),
						]
					);
					?>
				</td>
			</tr>
		</table>
		<?php
	}
}
