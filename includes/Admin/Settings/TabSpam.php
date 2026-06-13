<?php
/**
 * Spam Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

/**
 * Spam tab: registration spam protection (proof-of-render token, honeypot,
 * auto-ban).
 */
final class TabSpam implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'spam';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Spam', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-shield-alt';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		$this->render_section(
			__( 'Registration Protection', 'lw-firewall' ),
			__( 'Block bot sign-ups on wp-login.php?action=register without a captcha. Active only when "Anyone can register" is enabled in Settings → General.', 'lw-firewall' ),
			SpamFields::registration()
		);

		$this->render_section(
			__( 'Registration Auto-Ban', 'lw-firewall' ),
			__( 'Ban IPs that repeatedly submit spam registrations. A banned IP is blocked from the whole site, not just the registration form.', 'lw-firewall' ),
			SpamFields::auto_ban()
		);
	}

	/**
	 * Render a settings section: heading, intro and a form-table of rows.
	 *
	 * @param string                              $heading Section heading.
	 * @param string                              $intro   Section description.
	 * @param array<string, array<string, mixed>> $rows    Field rows keyed by option name.
	 */
	private function render_section( string $heading, string $intro, array $rows ): void {
		?>
		<h2><?php echo esc_html( $heading ); ?></h2>
		<p class="lw-firewall-section-description"><?php echo esc_html( $intro ); ?></p>

		<table class="form-table">
			<?php
			foreach ( $rows as $name => $row ) {
				$this->render_row( $name, $row );
			}
			?>
		</table>
		<?php
	}

	/**
	 * Render a single form-table row (checkbox by default, number when typed).
	 *
	 * @param string               $name Option name.
	 * @param array<string, mixed> $row  Row config (th, label, desc, type, min, max).
	 */
	private function render_row( string $name, array $row ): void {
		?>
		<tr>
			<th scope="row"><?php echo esc_html( (string) ( $row['th'] ?? $row['label'] ?? '' ) ); ?></th>
			<td>
				<?php
				if ( 'number' === ( $row['type'] ?? '' ) ) {
					$this->render_number_field(
						[
							'name'        => $name,
							'min'         => (int) $row['min'],
							'max'         => (int) $row['max'],
							'description' => (string) $row['desc'],
						]
					);
				} else {
					$this->render_checkbox_field(
						[
							'name'        => $name,
							'label'       => (string) $row['label'],
							'description' => (string) $row['desc'],
						]
					);
				}
				?>
			</td>
		</tr>
		<?php
	}
}
