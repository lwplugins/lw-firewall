<?php
/**
 * One-time notice about retired filter_params entries.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin;

use LightweightPlugins\Firewall\Upgrade\FilterParamsMigration;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Tells the administrator which custom Filter Parameters entries stopped
 * being rate-limited when the list was retired, until they dismiss it.
 */
final class FilterParamsNotice {

	/**
	 * The admin-post action that dismisses the notice.
	 */
	private const ACTION = 'lw_firewall_dismiss_filter_params';

	/**
	 * Register the hooks when there is something to report.
	 *
	 * @return void
	 */
	public static function register(): void {
		add_action( 'admin_post_' . self::ACTION, [ self::class, 'dismiss' ] );

		if ( [] !== self::entries() ) {
			add_action( 'admin_notices', [ self::class, 'render' ] );
		}
	}

	/**
	 * Render the notice.
	 *
	 * @return void
	 */
	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$url = wp_nonce_url( admin_url( 'admin-post.php?action=' . self::ACTION ), self::ACTION );
		?>
		<div class="notice notice-warning lw-notice">
			<p><strong><?php esc_html_e( 'LW Firewall — Filter Parameters setting removed', 'lw-firewall' ); ?></strong></p>
			<p><?php esc_html_e( 'WooCommerce filter requests are now recognised automatically and protected by the visitor-cookie check plus the per-IP rate limit. These custom entries have no replacement and are no longer rate-limited:', 'lw-firewall' ); ?></p>
			<p><code><?php echo esc_html( implode( ', ', self::entries() ) ); ?></code></p>
			<p><a class="button" href="<?php echo esc_url( $url ); ?>"><?php esc_html_e( 'Dismiss', 'lw-firewall' ); ?></a></p>
		</div>
		<?php
	}

	/**
	 * Dismiss the notice (admin-post handler).
	 *
	 * @return void
	 */
	public static function dismiss(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'lw-firewall' ), '', [ 'response' => 403 ] );
		}

		check_admin_referer( self::ACTION );
		delete_option( FilterParamsMigration::DROPPED_OPTION );

		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url() );
		exit;
	}

	/**
	 * The recorded entries.
	 *
	 * @return array<int, string>
	 */
	private static function entries(): array {
		$entries = get_option( FilterParamsMigration::DROPPED_OPTION, [] );

		return is_array( $entries ) ? array_map( 'strval', $entries ) : [];
	}
}
