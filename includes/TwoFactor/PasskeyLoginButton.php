<?php
/**
 * "Sign in with a passkey" button on the wp-login.php form.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\Rest\Admin\Routes;
use LightweightPlugins\Firewall\TwoFactor\Passkey\WebAuthnFactory;
use LightweightPlugins\Firewall\TwoFactor\Rest\PasskeyLoginController;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registered by TwoFactorModule only while `twofa_passkey_login` is on.
 * Printed hidden: assets/js/twofa-login.js shows it only when the browser has
 * WebAuthn (window.PublicKeyCredential), then runs the passwordless ceremony
 * against PasskeyLoginController. Conditional mediation (autofill) is not
 * offered: it would issue a challenge on every login page view.
 */
final class PasskeyLoginButton {

	/**
	 * Register the hook.
	 */
	public function register(): void {
		add_action( 'login_form', array( $this, 'render' ) );
	}

	/**
	 * `login_form`: the hidden button (nothing when passkeys cannot work here).
	 */
	public function render(): void {
		if ( ! WebAuthnFactory::available() ) {
			return;
		}

		ChallengePage::enqueue_script();
		$base = Routes::NAMESPACE . PasskeyLoginController::BASE;
		?>
		<div class="lwfw-passkey-login" id="lwfw-passkey-login" hidden
			data-options-url="<?php echo esc_url( rest_url( $base . '/options' ) ); ?>"
			data-verify-url="<?php echo esc_url( rest_url( $base . '/verify' ) ); ?>"
			data-error="<?php echo esc_attr__( 'The passkey sign-in did not finish. Try again or sign in with your password.', 'lw-firewall' ); ?>">
			<p style="margin-bottom:16px">
				<button type="button" class="button button-secondary button-large" id="lwfw-passkey-login-button" style="width:100%;display:inline-flex;align-items:center;justify-content:center;gap:8px">
					<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 20 3"/><path d="M16 7l3 3"/><path d="M13.5 9.5l2 2"/></svg>
					<span><?php esc_html_e( 'Sign in with a passkey', 'lw-firewall' ); ?></span>
				</button>
			</p>
		</div>
		<?php
	}
}
