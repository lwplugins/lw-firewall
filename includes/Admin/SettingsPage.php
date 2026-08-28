<?php
/**
 * Settings Page class.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin;

use LightweightPlugins\Firewall\Admin\Settings\TabAlerts;
use LightweightPlugins\Firewall\Admin\Settings\TabBots;
use LightweightPlugins\Firewall\Admin\Settings\TabGeneral;
use LightweightPlugins\Firewall\Admin\Settings\TabGeo;
use LightweightPlugins\Firewall\Admin\Settings\TabImportExport;
use LightweightPlugins\Firewall\Admin\Settings\TabInterface;
use LightweightPlugins\Firewall\Admin\Settings\TabIpRules;
use LightweightPlugins\Firewall\Admin\Settings\TabLogs;
use LightweightPlugins\Firewall\Admin\Settings\TabProtection;
use LightweightPlugins\Firewall\Admin\Settings\TabSecurity;
use LightweightPlugins\Firewall\Admin\Settings\TabSpam;
use LightweightPlugins\Firewall\Admin\Settings\TabStatus;
use LightweightPlugins\Firewall\Options;

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
			new TabSpam(),
			new TabBots(),
			new TabIpRules(),
			new TabGeo(),
			new TabSecurity(),
			new TabAlerts(),
			new TabStatus(),
			new TabLogs(),
			new TabImportExport(),
		];

		add_action( 'admin_menu', [ $this, 'add_menu_page' ] );
		add_action( 'admin_init', [ SettingsSaver::class, 'maybe_save' ] );
		add_action( 'admin_init', [ ImportExportHandler::class, 'maybe_handle' ] );
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
			[],
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
				<img src="<?php echo esc_url( LW_FIREWALL_URL . 'assets/img/title-icon.svg' ); ?>" alt="" class="lw-title-icon" />
				<?php esc_html_e( 'Lightweight Firewall', 'lw-firewall' ); ?>
				<span style="font-size: 13px; font-weight: 400; color: #888;">(<?php echo esc_html( LW_FIREWALL_VERSION ); ?>)</span>
			</h1>

			<?php if ( isset( $_GET['updated'] ) && '1' === $_GET['updated'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success lw-notice is-dismissible">
					<p><?php esc_html_e( 'Settings saved.', 'lw-firewall' ); ?></p>
				</div>
			<?php endif; ?>

			<?php $this->render_action_notice(); ?>
			<?php $this->render_locked_notice(); ?>

			<form method="post" action="" enctype="multipart/form-data">
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
	 * Warn that some fields are pinned by a wp-config.php constant.
	 *
	 * Without this an operator can edit a locked field, save it, and see no
	 * sign that the runtime is still using the constant.
	 *
	 * @return void
	 */
	private function render_locked_notice(): void {
		$locked = Options::overridden();

		if ( empty( $locked ) ) {
			return;
		}

		printf(
			'<div class="notice notice-info lw-notice"><p>%s<br /><code>%s</code></p></div>',
			esc_html__( 'These settings are pinned by a constant in wp-config.php. Editing them here has no effect until the constant is removed:', 'lw-firewall' ),
			esc_html( implode( ', ', array_map( static fn ( string $key ): string => Options::CONST_PREFIX . strtoupper( $key ), $locked ) ) )
		);
	}

	/**
	 * Render the outcome notice for an Alerts tab action.
	 *
	 * @return void
	 */
	private function render_action_notice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display of an action outcome.
		$notice = isset( $_GET['lw_notice'] ) ? sanitize_key( wp_unslash( $_GET['lw_notice'] ) ) : '';

		$notices = [
			'test_sent'     => [ 'success', __( 'Test alert sent. If it does not arrive, the problem is your site mail configuration, not the firewall.', 'lw-firewall' ) ],
			'test_failed'   => [ 'error', __( 'The test alert could not be sent — wp_mail() refused it. Check your SMTP plugin or hosting mail limits.', 'lw-firewall' ) ],
			'scan_clean'    => [ 'success', __( 'Scan finished: no new or modified administrators found.', 'lw-firewall' ) ],
			'scan_found'    => [ 'warning', __( 'Scan finished: new or modified administrators were found and an alert email was sent.', 'lw-firewall' ) ],
			'unban_done'    => [ 'success', __( 'IP unblocked. Its rate-limit, login, registration and password-reset counters were cleared too, so the next request starts from zero.', 'lw-firewall' ) ],
			'unban_all'     => [ 'success', __( 'All tracked bans lifted and their counters cleared.', 'lw-firewall' ) ],
			'unban_failed'  => [ 'error', __( 'The ban could not be lifted — the storage backend refused the delete. Check the Status tab for the active backend.', 'lw-firewall' ) ],
			'unban_invalid' => [ 'error', __( 'That is not a valid IP address.', 'lw-firewall' ) ],
		];

		if ( ! isset( $notices[ $notice ] ) ) {
			return;
		}

		printf(
			'<div class="notice notice-%s lw-notice is-dismissible"><p>%s</p></div>',
			esc_attr( $notices[ $notice ][0] ),
			esc_html( $notices[ $notice ][1] )
		);
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
