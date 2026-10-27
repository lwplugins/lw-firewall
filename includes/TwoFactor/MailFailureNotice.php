<?php
/**
 * Admin notice: two-factor enrollment e-mails cannot be sent.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shown to administrators (manage_options) after EnrollmentMail could not
 * send a code: forced enrollments then bind without the e-mail check. A
 * nonce'd admin-post link dismisses it; a later successful mail clears it.
 */
final class MailFailureNotice {

	/**
	 * The admin-post action that dismisses the notice.
	 */
	public const ACTION = 'lw_firewall_dismiss_2fa_mail';

	/**
	 * Register the hooks.
	 */
	public function register(): void {
		add_action( 'admin_notices', array( $this, 'render' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'dismiss' ) );
	}

	/**
	 * Print the notice when the flag is set.
	 */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) || ! get_option( EnrollmentMail::FAILED_OPTION ) ) {
			return;
		}

		$url = wp_nonce_url( admin_url( 'admin-post.php?action=' . self::ACTION ), self::ACTION );
		?>
		<div class="notice notice-error lw-notice">
			<p>
				<span class="dashicons dashicons-email-alt" aria-hidden="true"></span>
				<strong><?php esc_html_e( 'LW Firewall: two-factor setup e-mails cannot be sent', 'lw-firewall' ); ?></strong>
			</p>
			<p><?php esc_html_e( 'This site could not send the e-mail code that confirms a forced two-factor setup at sign-in. Until e-mail works, those setups go ahead with the password alone. Check the site\'s e-mail sending.', 'lw-firewall' ); ?></p>
			<p><a class="button" href="<?php echo esc_url( $url ); ?>"><?php esc_html_e( 'Dismiss', 'lw-firewall' ); ?></a></p>
		</div>
		<?php
	}

	/**
	 * Dismiss (admin-post handler).
	 */
	public function dismiss(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'lw-firewall' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION );
		delete_option( EnrollmentMail::FAILED_OPTION );

		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url() );
		exit;
	}
}
