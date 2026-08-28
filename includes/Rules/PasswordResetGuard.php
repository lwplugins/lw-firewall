<?php
/**
 * Password-reset spam guard.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\Options;
use WP_Error;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Blocks password-reset floods at `lostpassword_post`.
 *
 * That hook is the one chokepoint every reset request passes through: core's
 * retrieve_password() fires it, and so does WooCommerce's own copy on the
 * my-account form — and both abort when the WP_Error handed to the hook comes
 * back with errors. Hooking the form instead would cover only one of them.
 *
 * Requests initiated by a privileged user or by WP-CLI are exempt, so the
 * "Send password reset link" row action in Users and any provisioning script
 * keep working no matter how loud the front end is.
 */
final class PasswordResetGuard {

	/**
	 * Verdict for a submission that failed the proof-of-render check.
	 */
	public const SPAM = 'spam';

	/**
	 * Hidden token field name.
	 */
	private const TOKEN_FIELD = 'lw_fw_reset_token';

	/**
	 * Honeypot field name (must look innocuous to bots).
	 */
	private const HONEYPOT_FIELD = 'lw_fw_confirm_url';

	/**
	 * Register the guard's hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'lostpassword_form', [ self::class, 'render_fields' ] );
		add_action( 'lostpassword_post', [ self::class, 'guard' ], 10, 2 );

		if ( ! empty( Options::get( 'reset_block_admins' ) ) ) {
			add_filter( 'allow_password_reset', [ self::class, 'filter_allow_reset' ], 10, 2 );
		}
	}

	/**
	 * Inject the proof-of-render token (and honeypot) into the lost-password
	 * form. This hook only fires on wp-login.php, which is why the token is
	 * only ever *required* there.
	 *
	 * @return void
	 */
	public static function render_fields(): void {
		if ( empty( Options::get( 'reset_proof_enabled' ) ) ) {
			return;
		}

		printf(
			'<input type="hidden" name="%s" value="%s" />',
			esc_attr( self::TOKEN_FIELD ),
			esc_attr( RegisterToken::issue( 'reset' ) )
		);

		printf(
			'<p style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true"><label>%s<input type="text" name="%s" tabindex="-1" autocomplete="off" value="" /></label></p>',
			esc_html__( 'Leave this field empty', 'lw-firewall' ),
			esc_attr( self::HONEYPOT_FIELD )
		);
	}

	/**
	 * Decide whether this reset request may proceed.
	 *
	 * Both parameters are hook payloads, so neither type is guaranteed: core
	 * and WooCommerce pass a WP_Error and a WP_User|false, but any plugin may
	 * fire this action with something else. They are validated, not declared.
	 *
	 * @param mixed $errors    Errors collected so far; adding to it aborts the reset.
	 * @param mixed $user_data Target account, or false when unknown.
	 * @return void
	 */
	public static function guard( $errors, $user_data = false ): void {
		if ( ! $errors instanceof WP_Error || $errors->has_errors() ) {
			return;
		}

		$ip = IpDetector::get_ip();

		if ( self::is_exempt( $ip ) ) {
			return;
		}

		$limiter = self::limiter();
		$user_id = $user_data instanceof WP_User ? (int) $user_data->ID : 0;

		// A submission that failed the proof-of-render check is bot traffic, not
		// a real request for that account. It counts against the sender so a
		// flood still gets banned, but it must not burn the target's allowance
		// or the site's email budget — a bot could otherwise lock a user out of
		// their own reset, or deny resets to everyone.
		if ( self::is_login_form_request() && ! self::proof_ok() ) {
			$limiter->record_rejected( $ip );
			$errors->add( 'lw_fw_reset_blocked', ResetPenalty::message( self::SPAM ) );
			ResetPenalty::apply( self::SPAM, $ip, $user_id );

			return;
		}

		$verdict = $limiter->record( $ip, $user_id );

		if ( ResetLimiter::ALLOW === $verdict ) {
			return;
		}

		$errors->add( 'lw_fw_reset_blocked', ResetPenalty::message( $verdict ) );

		ResetPenalty::apply( $verdict, $ip, $user_id );
	}

	/**
	 * Refuse password resets for administrator accounts.
	 *
	 * Opt-in hardening: it closes the "flood the admin's inbox, then phish the
	 * reset link" path entirely, at the cost of needing WP-CLI or another
	 * administrator to recover a locked-out admin.
	 *
	 * @param bool|\WP_Error $allow   Whether a reset is allowed.
	 * @param int            $user_id Target user ID.
	 * @return bool|\WP_Error
	 */
	public static function filter_allow_reset( $allow, $user_id ) {
		// Known trade: refusing here makes WordPress answer with its own
		// no_password_reset error, which differs from the generic response an
		// ordinary account gets — so a determined attacker can enumerate which
		// accounts are privileged. Closing it needs the same generic-response
		// handling as lost-password user enumeration, which does not exist yet;
		// the setting is opt-in and off by default until it does.

		if ( self::is_exempt( IpDetector::get_ip() ) ) {
			return $allow;
		}

		$user = get_userdata( (int) $user_id );

		if ( ! $user instanceof WP_User ) {
			return $allow;
		}

		// Role slug alone missed multisite super admins and any custom role
		// carrying administrative capability, which is exactly who this setting
		// exists to protect.
		$privileged = in_array( 'administrator', (array) $user->roles, true )
			|| ( is_multisite() && is_super_admin( (int) $user_id ) )
			|| user_can( $user, 'manage_options' );

		return $privileged ? false : $allow;
	}

	/**
	 * Build the limiter from the current settings.
	 *
	 * @return ResetLimiter
	 */
	private static function limiter(): ResetLimiter {
		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );

		return new ResetLimiter(
			$storage,
			[
				'ip_max'        => (int) Options::get( 'reset_ip_max', 5 ),
				'ip_window'     => (int) Options::get( 'reset_ip_window', 900 ),
				'user_max'      => (int) Options::get( 'reset_user_max', 3 ),
				'user_window'   => (int) Options::get( 'reset_user_window', 3600 ),
				'global_max'    => (int) Options::get( 'reset_global_max', 30 ),
				'global_window' => HOUR_IN_SECONDS,
			]
		);
	}

	/**
	 * Whether this request bypasses every check.
	 *
	 * @param string $ip Requesting IP.
	 * @return bool
	 */
	private static function is_exempt( string $ip ): bool {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}

		// The Users screen "Send password reset link" action calls
		// retrieve_password() too; an administrator doing that on purpose is
		// never the flood we are looking for.
		if ( current_user_can( 'edit_users' ) ) {
			return true;
		}

		$whitelist = (array) Options::get( 'ip_whitelist', [] );

		return ! empty( $whitelist ) && IpMatcher::matches( $ip, $whitelist );
	}

	/**
	 * Whether this POST came from the wp-login.php form we injected fields into.
	 *
	 * WooCommerce (and any other plugin with its own lost-password template)
	 * never renders our token, so the proof check must not apply there.
	 *
	 * @return bool
	 */
	private static function is_login_form_request(): bool {
		if ( empty( Options::get( 'reset_proof_enabled' ) ) ) {
			return false;
		}

		return isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'];
	}

	/**
	 * Run the honeypot and proof-of-render checks.
	 *
	 * @return bool True when the submission looks human.
	 */
	private static function proof_ok(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only spam check on the core lost-password POST; no state change.
		$honeypot = isset( $_POST[ self::HONEYPOT_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::HONEYPOT_FIELD ] ) ) : '';

		if ( '' !== $honeypot ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only spam check on the core lost-password POST; no state change.
		$token = isset( $_POST[ self::TOKEN_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::TOKEN_FIELD ] ) ) : '';

		if ( '' === $token ) {
			return false;
		}

		$max_age = (int) Options::get( 'reset_token_max_age', 3600 );
		$storage = null;

		if ( ! empty( Options::get( 'reset_single_use' ) ) ) {
			$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		}

		// Scoped to 'reset' so a lost-password token can never consume the
		// single-use entry of a registration token rendered in the same second.
		return RegisterToken::verify(
			$token,
			(int) Options::get( 'reset_min_fill_time', 2 ),
			$max_age,
			$storage,
			'reset'
		);
	}
}
