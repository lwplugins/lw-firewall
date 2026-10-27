<?php
/**
 * The forced-enrollment screens on wp-login.php.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Same frame as ChallengePage (core login_header()/login_footer()) and the
 * same action URL and nonce. The setup key is printed as text, in an
 * otpauth:// link and as a QR code (QrScript draws it from a data attribute),
 * never in a form field.
 */
final class EnrollmentPage {

	/**
	 * Setup screen: the key, the authenticator link and the code field.
	 *
	 * @param string      $token  Pending token.
	 * @param WP_User     $user   Pending user.
	 * @param string      $secret Base32 secret.
	 * @param string      $error   Error message ('' = none).
	 * @param string|null $mail_to Masked address the e-mail code went to; null = no e-mail step.
	 */
	public function render_setup( string $token, WP_User $user, string $secret, string $error, ?string $mail_to = null ): void {
		$uri = Totp::site_uri( $secret, (string) $user->user_login );
		QrScript::enqueue();

		login_header( __( 'Set up two-factor authentication', 'lw-firewall' ), '', ChallengePage::errors( $error ) );
		?>
		<form name="lwfw2faform" id="lwfw-2fa-form" class="lwfw-2fa-enroll" action="<?php echo esc_url( ChallengePage::url( $token ) ); ?>" method="post" autocomplete="off">
			<p><?php esc_html_e( 'Your account must use two-factor authentication. Scan the QR code or add this key to your authenticator app, then enter the 6-digit code the app shows.', 'lw-firewall' ); ?></p>
			<p class="lwfw-2fa-key">
				<strong><?php esc_html_e( 'Setup key', 'lw-firewall' ); ?></strong><br />
				<code><?php echo esc_html( implode( ' ', str_split( $secret, 4 ) ) ); ?></code>
			</p>
			<div class="lwfw-2fa-qr" <?php echo esc_attr( QrScript::ATTRIBUTE ); ?>="<?php echo esc_attr( $uri ); ?>" aria-label="<?php esc_attr_e( 'QR code for your authenticator app', 'lw-firewall' ); ?>" role="img"></div>
			<p><a href="<?php echo esc_url( $uri, array( 'otpauth' ) ); ?>"><?php esc_html_e( 'Open in your authenticator app', 'lw-firewall' ); ?></a></p>
			<p class="description"><?php esc_html_e( 'This key is valid for 10 minutes. If you start over, you get a new key: delete the old entry from your app.', 'lw-firewall' ); ?></p>
			<?php $this->render_mail_field( $mail_to ); ?>
			<?php $this->hidden_fields( $token ); ?>
			<input type="hidden" name="lwfw_method" value="<?php echo esc_attr( SecondFactorVerifier::TOTP ); ?>" />
			<p>
				<label for="lwfw-2fa-code"><?php esc_html_e( 'Code from your authenticator app', 'lw-firewall' ); ?></label>
				<input type="text" name="lwfw_code" id="lwfw-2fa-code" class="input" value="" size="20" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" />
			</p>
			<p class="submit">
				<input type="submit" name="wp-submit" id="lwfw-2fa-submit" class="button button-primary button-large" value="<?php echo esc_attr__( 'Turn on and continue', 'lw-firewall' ); ?>" />
			</p>
		</form>
		<?php
		$this->render_nav();
		login_footer( 'lwfw-2fa-code' );
	}

	/**
	 * The "continue" step: the recovery codes right after the confirmation,
	 * or (any later visit) only a note that they were shown.
	 *
	 * @param string   $token Pending token.
	 * @param string[] $codes Plain recovery codes; empty = already shown.
	 */
	public function render_continue( string $token, array $codes ): void {
		login_header( __( 'Save your recovery codes', 'lw-firewall' ), '', ChallengePage::errors( '' ) );
		?>
		<form name="lwfw2faform" id="lwfw-2fa-form" class="lwfw-2fa-codes" action="<?php echo esc_url( ChallengePage::url( $token ) ); ?>" method="post" autocomplete="off">
			<?php if ( array() !== $codes ) : ?>
				<p><?php esc_html_e( 'Two-factor authentication is on. If you lose your phone, each of these codes signs you in once. Save them now: they are shown only this time.', 'lw-firewall' ); ?></p>
				<ol class="lwfw-2fa-recovery-list">
					<?php foreach ( $codes as $code ) : ?>
						<li><code><?php echo esc_html( $code ); ?></code></li>
					<?php endforeach; ?>
				</ol>
			<?php else : ?>
				<p><?php esc_html_e( 'Two-factor authentication is on. Your recovery codes were shown once; if you did not save them, create new ones on your profile after signing in.', 'lw-firewall' ); ?></p>
			<?php endif; ?>
			<?php $this->hidden_fields( $token ); ?>
			<input type="hidden" name="lwfw_step" value="continue" />
			<p class="submit">
				<input type="submit" name="wp-submit" id="lwfw-2fa-submit" class="button button-primary button-large" value="<?php echo esc_attr( array() !== $codes ? __( 'I saved them, continue', 'lw-firewall' ) : __( 'Continue', 'lw-firewall' ) ); ?>" />
			</p>
		</form>
		<?php
		login_footer();
	}

	/**
	 * The e-mail code field (when the code was sent).
	 *
	 * @param string|null $mail_to Masked address; null = no e-mail step.
	 */
	private function render_mail_field( ?string $mail_to ): void {
		if ( null === $mail_to ) {
			return;
		}
		?>
		<p>
			<label for="lwfw-2fa-mail-code">
				<?php
				/* translators: %s: masked e-mail address */
				echo esc_html( '' !== $mail_to ? sprintf( __( 'Code we e-mailed to %s', 'lw-firewall' ), $mail_to ) : __( 'Code we e-mailed to you', 'lw-firewall' ) );
				?>
			</label>
			<input type="text" name="lwfw_mail_code" id="lwfw-2fa-mail-code" class="input" value="" size="20" autocomplete="off" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" />
		</p>
		<?php
	}

	/**
	 * Token and nonce fields (the secret is never one of them).
	 *
	 * @param string $token Pending token.
	 */
	private function hidden_fields( string $token ): void {
		?>
		<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
		<?php
		wp_nonce_field( 'lw_firewall_2fa_' . $token, 'lwfw_2fa_nonce', false );
	}

	/**
	 * Back to the login form.
	 */
	private function render_nav(): void {
		echo '<p id="nav"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Start over', 'lw-firewall' ) . '</a></p>';
	}
}
