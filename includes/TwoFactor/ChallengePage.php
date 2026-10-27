<?php
/**
 * The second-factor screen on wp-login.php.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use WP_Error;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders with core login_header()/login_footer(), so the screen looks like
 * the login form and keeps core's login page protections: wp-login.php sends
 * nocache_headers() itself, and `login_init` sends X-Frame-Options SAMEORIGIN
 * (send_frame_options_header) before our `login_form_*` action runs.
 */
final class ChallengePage {

	/**
	 * The wp-login.php action of the screen.
	 */
	public const ACTION = 'lw_firewall_2fa';

	/**
	 * Script handle of the passkey button.
	 */
	public const SCRIPT_HANDLE = 'lw-firewall-twofa-login';

	/**
	 * Screen modes.
	 */
	public const MODE_TOTP     = 'totp';
	public const MODE_RECOVERY = 'recovery';
	public const MODE_PASSKEY  = 'passkey';

	/**
	 * URL of the screen for a pending token.
	 *
	 * @param string $token Pending token.
	 * @param string $mode  '' or MODE_RECOVERY.
	 */
	public static function url( string $token, string $mode = '' ): string {
		$args = array(
			'action' => self::ACTION,
			'token'  => $token,
		);
		if ( '' !== $mode ) {
			$args['mode'] = $mode;
		}

		return add_query_arg( $args, site_url( 'wp-login.php', 'login_post' ) );
	}

	/**
	 * Render the challenge.
	 *
	 * @param string               $token Pending token.
	 * @param WP_User              $user  Pending user.
	 * @param string               $error Error to show ('' = none).
	 * @param array<string, mixed> $view  mode (string), totp/recovery (bool), passkey (options array|null).
	 */
	public function render( string $token, WP_User $user, string $error, array $view = array() ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Part of the screen contract; the account is not shown.
		$mode    = (string) ( $view['mode'] ?? self::MODE_TOTP );
		$passkey = is_array( $view['passkey'] ?? null ) ? $view['passkey'] : null;
		$field   = self::MODE_RECOVERY === $mode ? 'lwfw-2fa-recovery-code' : 'lwfw-2fa-code';

		if ( null !== $passkey ) {
			$this->enqueue_script();
		}

		login_header( __( 'Two-factor authentication', 'lw-firewall' ), '', self::errors( $error ) );
		$this->render_form( $token, $mode, $passkey );
		$this->render_links( $token, $mode, ! empty( $view['totp'] ), ! empty( $view['recovery'] ) );
		login_footer( self::MODE_PASSKEY === $mode ? '' : $field );
	}

	/**
	 * The "start over" screen of an expired, used up or unknown token.
	 *
	 * @param bool $locked Whether it ended after too many wrong answers.
	 */
	public function render_expired( bool $locked ): void {
		$message = $locked
			? __( 'Too many wrong answers. Sign in again to get a new chance.', 'lw-firewall' )
			: __( 'This sign-in has expired or was already used. Sign in again.', 'lw-firewall' );

		login_header( __( 'Two-factor authentication', 'lw-firewall' ), '', self::errors( $message ) );
		echo '<p id="nav"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Start over', 'lw-firewall' ) . '</a></p>';
		login_footer();
	}

	/**
	 * The form.
	 *
	 * @param string                    $token   Pending token.
	 * @param string                    $mode    Screen mode.
	 * @param array<string, mixed>|null $passkey Assertion options, or null.
	 */
	private function render_form( string $token, string $mode, ?array $passkey ): void {
		?>
		<form name="lwfw2faform" id="lwfw-2fa-form" action="<?php echo esc_url( self::url( $token ) ); ?>" method="post" autocomplete="off">
			<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
			<input type="hidden" name="lwfw_method" id="lwfw-2fa-method" value="<?php echo esc_attr( self::MODE_PASSKEY === $mode ? '' : $mode ); ?>" />
			<input type="hidden" name="lwfw_passkey" id="lwfw-2fa-passkey" value="" />
			<?php wp_nonce_field( 'lw_firewall_2fa_' . $token, 'lwfw_2fa_nonce', false ); ?>
			<?php $this->render_code_field( $mode ); ?>
			<?php if ( null !== $passkey ) : ?>
				<p class="lwfw-2fa-passkey">
					<button type="button" class="button button-secondary button-large" id="lwfw-2fa-passkey-button" data-options="<?php echo esc_attr( (string) wp_json_encode( $passkey ) ); ?>" data-error="<?php echo esc_attr__( 'The passkey check did not finish. Try again or use another method.', 'lw-firewall' ); ?>">
						<?php esc_html_e( 'Use a passkey', 'lw-firewall' ); ?>
					</button>
				</p>
			<?php endif; ?>
		</form>
		<?php
	}

	/**
	 * The code input and the submit button (none in passkey-only mode).
	 *
	 * @param string $mode Screen mode.
	 */
	private function render_code_field( string $mode ): void {
		if ( self::MODE_PASSKEY === $mode ) {
			return;
		}

		if ( self::MODE_RECOVERY === $mode ) {
			?>
			<p>
				<label for="lwfw-2fa-recovery-code"><?php esc_html_e( 'Recovery code', 'lw-firewall' ); ?></label>
				<input type="text" name="lwfw_code" id="lwfw-2fa-recovery-code" class="input" value="" size="20" autocomplete="off" autocapitalize="off" spellcheck="false" />
			</p>
			<?php
		} else {
			?>
			<p>
				<label for="lwfw-2fa-code"><?php esc_html_e( 'Code from your authenticator app', 'lw-firewall' ); ?></label>
				<input type="text" name="lwfw_code" id="lwfw-2fa-code" class="input" value="" size="20" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" />
			</p>
			<?php
		}
		?>
		<p class="submit">
			<input type="submit" name="wp-submit" id="lwfw-2fa-submit" class="button button-primary button-large" value="<?php echo esc_attr__( 'Verify', 'lw-firewall' ); ?>" />
		</p>
		<?php
	}

	/**
	 * Links to the other methods and back to the login form.
	 *
	 * @param string $token    Pending token.
	 * @param string $mode     Screen mode.
	 * @param bool   $totp     Whether the user has an authenticator app.
	 * @param bool   $recovery Whether the user has recovery codes left.
	 */
	private function render_links( string $token, string $mode, bool $totp, bool $recovery ): void {
		echo '<p id="nav">';
		if ( self::MODE_RECOVERY !== $mode && $recovery ) {
			echo '<a href="' . esc_url( self::url( $token, self::MODE_RECOVERY ) ) . '">' . esc_html__( 'Use a recovery code', 'lw-firewall' ) . '</a> | ';
		} elseif ( self::MODE_RECOVERY === $mode && $totp ) {
			echo '<a href="' . esc_url( self::url( $token ) ) . '">' . esc_html__( 'Use your authenticator app', 'lw-firewall' ) . '</a> | ';
		}
		echo '<a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Start over', 'lw-firewall' ) . '</a>';
		echo '</p>';
	}

	/**
	 * The error box content for login_header() (core prints messages unescaped).
	 *
	 * @param string $message Plain text message.
	 */
	private static function errors( string $message ): WP_Error {
		$errors = new WP_Error();
		if ( '' !== $message ) {
			$errors->add( 'lwfw_2fa', esc_html( $message ) );
		}

		return $errors;
	}

	/**
	 * Enqueue the passkey script (printed by login_footer()).
	 */
	private function enqueue_script(): void {
		if ( ! defined( 'LW_FIREWALL_URL' ) || ! defined( 'LW_FIREWALL_VERSION' ) ) {
			return;
		}

		wp_enqueue_script( self::SCRIPT_HANDLE, LW_FIREWALL_URL . 'assets/js/twofa-login.js', array(), LW_FIREWALL_VERSION, true );
	}
}
