<?php
/**
 * Warning: two-factor login is on, but the plugin is not network-activated.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * On multisite the auth cookie is valid network-wide, but a site where the
 * plugin is not active never runs the login interceptor, so a password-only
 * sign-in there yields a session the protected sites accept. Enforcement is
 * impossible from here; the warning is the remedy. Shown in the network admin
 * (network plugin managers) and on the main site (site administrators); the
 * Two-Factor tab gets the same flag through the settings meta.
 */
final class NetworkActivationNotice {

	/**
	 * Register the hooks.
	 */
	public function register(): void {
		if ( ! is_multisite() ) {
			return;
		}

		add_action( 'network_admin_notices', array( $this, 'render_network' ) );
		add_action( 'admin_notices', array( $this, 'render_site' ) );
	}

	/**
	 * Whether the warning applies: multisite, two-factor on, and the plugin
	 * not active for the whole network.
	 */
	public static function required(): bool {
		if ( ! is_multisite() || ! Options::get( 'twofa_enabled', false ) ) {
			return false;
		}

		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return ! is_plugin_active_for_network( plugin_basename( LW_FIREWALL_FILE ) );
	}

	/**
	 * The warning text.
	 */
	public static function message(): string {
		return __( 'Two-factor login is on, but LW Firewall is not network-activated. On sites where the plugin is not active, people can still sign in with only a password, and that session is valid across the network. Network-activate LW Firewall to protect every site.', 'lw-firewall' );
	}

	/**
	 * Network admin: for users who can manage network plugins.
	 */
	public function render_network(): void {
		if ( current_user_can( 'manage_network_plugins' ) && self::required() ) {
			$this->print_notice();
		}
	}

	/**
	 * Main site admin: for users who can manage the site's options.
	 */
	public function render_site(): void {
		if ( is_main_site() && current_user_can( 'manage_options' ) && self::required() ) {
			$this->print_notice();
		}
	}

	/**
	 * Print the (not dismissible) notice.
	 */
	private function print_notice(): void {
		?>
		<div class="notice notice-warning lw-notice">
			<p>
				<span class="dashicons dashicons-warning" aria-hidden="true"></span>
				<?php echo esc_html( self::message() ); ?>
				<?php if ( current_user_can( 'manage_network_plugins' ) ) : ?>
					<a href="<?php echo esc_url( network_admin_url( 'plugins.php' ) ); ?>"><?php esc_html_e( 'Network plugins', 'lw-firewall' ); ?></a>
				<?php endif; ?>
			</p>
		</div>
		<?php
	}
}
