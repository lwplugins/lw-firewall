<?php
/**
 * Registration spam guard: injects and validates the proof-of-render token
 * plus an optional honeypot on the default WordPress registration form.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Options;
use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks `register_form` (inject fields) and `registration_errors` (validate).
 * Only loaded when register protection is enabled and registration is open.
 */
final class RegisterGuard {

	/**
	 * Hidden token field name.
	 */
	private const TOKEN_FIELD = 'lw_fw_reg_token';

	/**
	 * Honeypot field name (must look innocuous to bots).
	 */
	private const HONEYPOT_FIELD = 'lw_fw_url';

	/**
	 * Inject the token (and honeypot) into the rendered registration form.
	 *
	 * @return void
	 */
	public static function render_fields(): void {
		printf(
			'<input type="hidden" name="%s" value="%s" />',
			esc_attr( self::TOKEN_FIELD ),
			esc_attr( RegisterToken::issue() )
		);

		if ( empty( Options::get( 'register_honeypot' ) ) ) {
			return;
		}

		printf(
			'<p style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true"><label>%s<input type="text" name="%s" tabindex="-1" autocomplete="off" value="" /></label></p>',
			esc_html__( 'Leave this field empty', 'lw-firewall' ),
			esc_attr( self::HONEYPOT_FIELD )
		);
	}

	/**
	 * Validate the registration; reject and record spam on any failed check.
	 *
	 * @param WP_Error $errors Registration errors object.
	 * @param string   $login  Sanitized user login (unused).
	 * @param string   $email  User email (unused).
	 * @return WP_Error
	 */
	public static function validate( WP_Error $errors, string $login = '', string $email = '' ): WP_Error { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( self::is_spam() ) {
			RegisterTracker::record_reject();
			$errors->add( 'lw_fw_spam', __( 'Registration failed, please try again.', 'lw-firewall' ) );
		}

		return $errors;
	}

	/**
	 * Run the spam checks (honeypot, then token + timing + single-use).
	 *
	 * @return bool True when the submission looks like spam.
	 */
	private static function is_spam(): bool {
		if ( ! empty( Options::get( 'register_honeypot' ) ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only spam check on the core registration POST; no state change.
			$honeypot = isset( $_POST[ self::HONEYPOT_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::HONEYPOT_FIELD ] ) ) : '';

			if ( '' !== $honeypot ) {
				return true;
			}
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only spam check on the core registration POST; no state change.
		$token = isset( $_POST[ self::TOKEN_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::TOKEN_FIELD ] ) ) : '';

		if ( '' === $token ) {
			return true;
		}

		$min_fill = (int) Options::get( 'register_min_fill_time', 2 );
		$max_age  = (int) Options::get( 'register_token_max_age', 3600 );
		$storage  = null;

		if ( ! empty( Options::get( 'register_single_use' ) ) ) {
			$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		}

		return ! RegisterToken::verify( $token, $min_fill, $max_age, $storage );
	}
}
