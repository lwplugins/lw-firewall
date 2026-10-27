<?php
/**
 * Starts the two-factor login module.
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
 * Started from Plugin next to the alerts, independently of the MU-worker
 * health: a stale worker must not silently drop the second factor.
 *
 * Off unless `twofa_enabled` is on; `define( 'LW_FIREWALL_TWOFA_ENABLED', false )`
 * in wp-config.php pins it off (Options constant pinning) as the emergency
 * switch. Needs the sodium and openssl extensions: the TOTP secrets are
 * sealed with libsodium (WordPress' sodium_compat polyfill cannot securely
 * wipe memory and throws on sodium_memzero), passkeys need openssl.
 */
final class TwoFactorModule {

	/**
	 * Register the module for this request.
	 */
	public static function init(): void {
		self::boot( (bool) Options::get( 'twofa_enabled', false ), self::crypto_available() );
	}

	/**
	 * Register the hooks, or the "unavailable" notice.
	 *
	 * @param bool $enabled Whether two-factor login is switched on.
	 * @param bool $crypto  Whether the required PHP extensions are loaded.
	 * @return bool Whether the login hooks were registered.
	 */
	public static function boot( bool $enabled, bool $crypto ): bool {
		if ( ! $enabled ) {
			return false;
		}

		if ( ! $crypto ) {
			add_action( 'admin_notices', array( self::class, 'render_unavailable_notice' ) );
			add_action( 'network_admin_notices', array( self::class, 'render_unavailable_notice' ) );
			return false;
		}

		$signon   = new SignonTracker();
		$throttle = new FailureThrottle();
		$signon->register();
		( new LoginInterceptor( null, null, null, null, null, $signon, $throttle ) )->register();
		( new PasswordAuthGuard( null, $signon, $throttle ) )->register( (bool) Options::get( 'twofa_block_app_passwords', false ) );

		return true;
	}

	/**
	 * Whether the native sodium and the openssl extensions are loaded.
	 */
	public static function crypto_available(): bool {
		return extension_loaded( 'sodium' ) && extension_loaded( 'openssl' );
	}

	/**
	 * Admin notice: switched on, but this server cannot run it.
	 */
	public static function render_unavailable_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="notice notice-error lw-notice">
			<p>
				<span class="dashicons dashicons-warning" aria-hidden="true"></span>
				<strong><?php esc_html_e( 'LW Firewall: two-factor login is not active', 'lw-firewall' ); ?></strong>
			</p>
			<p><?php esc_html_e( 'Two-factor login is switched on, but this server is missing the PHP sodium or openssl extension. Until your host enables them, accounts sign in with their password only.', 'lw-firewall' ); ?></p>
		</div>
		<?php
	}
}
