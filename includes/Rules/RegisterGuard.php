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
use LightweightPlugins\Firewall\Storage\StorageInterface;
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
	 * Priority on registration_errors: after other plugins have added theirs.
	 */
	public const PRIORITY = 9999;

	/**
	 * Verdicts reached in this request, keyed by submitted token.
	 *
	 * @var array<string, string>
	 */
	private static array $verdicts = [];

	/**
	 * Tokens this request has spent.
	 *
	 * @var array<string, true>
	 */
	private static array $spent = [];

	/**
	 * Storage override (tests); null resolves the configured backend.
	 *
	 * @var StorageInterface|null
	 */
	private static ?StorageInterface $storage = null;

	/**
	 * Inject the token (and honeypot) into the rendered registration form.
	 *
	 * @return void
	 */
	public static function render_fields(): void {
		self::forbid_caching();

		printf(
			'<input type="hidden" name="%s" value="%s" />',
			esc_attr( self::TOKEN_FIELD ),
			esc_attr( RegisterToken::issue( 'reg' ) )
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
	 * Keep the page carrying a single-use token out of page caches.
	 *
	 * A cached copy hands one token to every visitor until it expires, and
	 * with single-use on only the first of them can register. Best effort:
	 * the cache plugin flag always works, the headers only while output has
	 * not started (a form rendered mid-page usually has).
	 *
	 * @return void
	 */
	private static function forbid_caching(): void {
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- The page-cache convention every cache plugin reads.
		}

		if ( headers_sent() ) {
			return;
		}

		nocache_headers();
		header( 'X-Accel-Expires: 0' );
	}

	/**
	 * Validate the registration; refuse anything that looks like spam.
	 *
	 * Hooked late so errors added by other plugins (terms box, password
	 * confirmation) are already present: a refused form does not spend the
	 * single-use token, and resending the same page is not a replay.
	 *
	 * The input is whatever the previously registered filters returned, so it
	 * is validated rather than declared. Hard-typing it turned any other
	 * plugin's non-WP_Error return into an uncatchable TypeError on a public
	 * registration form.
	 *
	 * @param mixed $errors Registration errors object.
	 * @param mixed $login  Sanitized user login (unused).
	 * @param mixed $email  User email (unused).
	 * @return mixed
	 */
	public static function validate( $errors = null, $login = '', $email = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( ! $errors instanceof WP_Error ) {
			return $errors;
		}

		if ( RegisterSpamCheck::OK !== self::verdict( $errors ) ) {
			$errors->add( 'lw_fw_spam', __( 'Registration failed, please try again.', 'lw-firewall' ) );
		}

		return $errors;
	}

	/**
	 * Forget this request's verdicts (seam for tests, which run several
	 * "requests" in one process).
	 *
	 * @param StorageInterface|null $storage Storage to use instead of the configured one.
	 * @return void
	 */
	public static function reset( ?StorageInterface $storage = null ): void {
		self::$verdicts = [];
		self::$spent    = [];
		self::$storage  = $storage;
	}

	/**
	 * The verdict for this request's submission, reached once per request.
	 *
	 * The registration_errors filter can run twice in one request — LearnDash
	 * applies it itself on register_post before core does. Judging (and
	 * spending, and counting) on every run refused every such registration
	 * as a replay of itself.
	 *
	 * @param WP_Error $errors Errors collected so far.
	 * @return string RegisterSpamCheck verdict.
	 */
	private static function verdict( WP_Error $errors ): string {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Read-only spam check on the core registration POST; no state change.
		$honeypot = isset( $_POST[ self::HONEYPOT_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::HONEYPOT_FIELD ] ) ) : '';
		$token    = isset( $_POST[ self::TOKEN_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::TOKEN_FIELD ] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( ! isset( self::$verdicts[ $token ] ) ) {
			self::$verdicts[ $token ] = self::judge( $honeypot, $token );
		}

		if ( RegisterSpamCheck::OK !== self::$verdicts[ $token ] || $errors->has_errors() || isset( self::$spent[ $token ] ) ) {
			return self::$verdicts[ $token ];
		}

		if ( self::spend( $token ) ) {
			self::$spent[ $token ] = true;
		} else {
			self::$verdicts[ $token ] = RegisterSpamCheck::REPLAYED;
		}

		return self::$verdicts[ $token ];
	}

	/**
	 * Judge the submission and count bot evidence toward the auto-ban.
	 *
	 * @param string $honeypot Submitted honeypot value.
	 * @param string $token    Submitted token.
	 * @return string RegisterSpamCheck verdict.
	 */
	private static function judge( string $honeypot, string $token ): string {
		$verdict = RegisterSpamCheck::evaluate(
			$honeypot,
			$token,
			[
				'honeypot' => ! empty( Options::get( 'register_honeypot' ) ),
				'min_fill' => (int) Options::get( 'register_min_fill_time', 2 ),
				'max_age'  => (int) Options::get( 'register_token_max_age', 3600 ),
			],
			time()
		);

		if ( RegisterSpamCheck::counts_toward_ban( $verdict ) ) {
			RegisterTracker::record_reject( 'register_spam', self::$storage );
		}

		return $verdict;
	}

	/**
	 * Spend the token when single-use is on.
	 *
	 * @param string $token Submitted token, already judged genuine.
	 * @return bool False when it had already been spent.
	 */
	private static function spend( string $token ): bool {
		if ( empty( Options::get( 'register_single_use' ) ) ) {
			return true;
		}

		$storage = self::$storage ?? lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );

		return RegisterToken::consume( $token, (int) Options::get( 'register_token_max_age', 3600 ), $storage, RegisterSpamCheck::SCOPE );
	}
}
