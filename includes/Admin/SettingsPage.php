<?php
/**
 * Settings Page class.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin;

use LightweightPlugins\Firewall\Admin\Settings\TabBots;
use LightweightPlugins\Firewall\Admin\Settings\TabGeneral;
use LightweightPlugins\Firewall\Admin\Settings\TabInterface;
use LightweightPlugins\Firewall\Admin\Settings\TabIpRules;
use LightweightPlugins\Firewall\Admin\Settings\TabLogs;
use LightweightPlugins\Firewall\Admin\Settings\TabProtection;
use LightweightPlugins\Firewall\Admin\Settings\TabSecurity;
use LightweightPlugins\Firewall\Admin\Settings\TabStatus;

/**
 * Handles the plugin settings page.
 */
final class SettingsPage {

	/**
	 * Settings page slug.
	 */
	public const SLUG = 'lw-firewall';

	/**
	 * Registered tabs.
	 *
	 * @var array<TabInterface>
	 */
	private array $tabs = [];

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->tabs = [
			new TabGeneral(),
			new TabProtection(),
			new TabBots(),
			new TabIpRules(),
			new TabSecurity(),
			new TabStatus(),
			new TabLogs(),
		];

		add_action( 'admin_menu', [ $this, 'add_menu_page' ] );
		add_action( 'admin_init', [ SettingsSaver::class, 'maybe_save' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
	}

	/**
	 * Add menu page.
	 *
	 * @return void
	 */
	public function add_menu_page(): void {
		ParentPage::maybe_register();

		add_submenu_page(
			ParentPage::SLUG,
			__( 'Firewall', 'lw-firewall' ),
			__( 'Firewall', 'lw-firewall' ),
			'manage_options',
			self::SLUG,
			[ $this, 'render' ]
		);
	}

	/**
	 * Enqueue admin assets.
	 *
	 * @param string $hook Current admin page.
	 * @return void
	 */
	public function enqueue_assets( string $hook ): void {
		$valid_hooks = [
			'toplevel_page_' . ParentPage::SLUG,
			ParentPage::SLUG . '_page_' . self::SLUG,
		];

		if ( ! in_array( $hook, $valid_hooks, true ) ) {
			return;
		}

		wp_enqueue_style(
			'lw-firewall-admin',
			LW_FIREWALL_URL . 'assets/css/admin.css',
			[],
			LW_FIREWALL_VERSION
		);

		wp_enqueue_script(
			'lw-firewall-admin',
			LW_FIREWALL_URL . 'assets/js/admin.js',
			[ 'jquery' ],
			LW_FIREWALL_VERSION,
			true
		);
	}

	/**
	 * Render settings page.
	 *
	 * @return void
	 */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		?>
		<div class="wrap">
			<h1>
				<img src="<?php echo esc_url( LW_FIREWALL_URL . 'assets/img/shield-star.svg' ); ?>" alt="" class="lw-firewall-title-icon" />
				<?php echo esc_html( get_admin_page_title() ); ?>
			</h1>

			<?php if ( isset( $_GET['updated'] ) && '1' === $_GET['updated'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success lw-notice is-dismissible">
					<p><?php esc_html_e( 'Settings saved.', 'lw-firewall' ); ?></p>
				</div>
			<?php endif; ?>

			<form method="post" action="">
				<?php wp_nonce_field( 'lw_firewall_save', '_lw_firewall_nonce' ); ?>
				<input type="hidden" name="lw_firewall_active_tab" value="" />

				<div class="lw-firewall-settings">
					<?php $this->render_tabs_nav(); ?>

					<div class="lw-firewall-tab-content">
						<?php $this->render_tabs_content(); ?>
						<?php submit_button( __( 'Save Changes', 'lw-firewall' ), 'primary', 'lw_firewall_save' ); ?>
					</div>
				</div>
			</form>
		</div>
		<?php
	}

	/**
	 * Render tabs navigation.
	 *
	 * @return void
	 */
	private function render_tabs_nav(): void {
		?>
		<ul class="lw-firewall-tabs">
			<?php foreach ( $this->tabs as $index => $tab ) : ?>
				<li>
					<a href="#<?php echo esc_attr( $tab->get_slug() ); ?>" <?php echo 0 === $index ? 'class="active"' : ''; ?>>
						<span class="dashicons <?php echo esc_attr( $tab->get_icon() ); ?>"></span>
						<?php echo esc_html( $tab->get_label() ); ?>
					</a>
				</li>
			<?php endforeach; ?>
		</ul>
		<?php
	}

	/**
	 * Render tabs content.
	 *
	 * @return void
	 */
	private function render_tabs_content(): void {
		foreach ( $this->tabs as $index => $tab ) {
			$active_class = 0 === $index ? ' active' : '';
			printf(
				'<div id="tab-%s" class="lw-firewall-tab-panel%s">',
				esc_attr( $tab->get_slug() ),
				esc_attr( $active_class )
			);
			$tab->render();
			echo '</div>';
		}
	}
}
