<?php
/**
 * Refuses password-only sign-ins of two-factor users outside the login screen.
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
 * Fail closed: for a user with a second factor, an `authenticate` result is
 * let through only when it happens inside an interactive core wp_signon()
 * (SignonTracker), where LoginInterceptor then asks for the second factor.
 * Everything else that reaches `authenticate` with the account password is
 * refused: XML-RPC, REST password-auth plugins, AJAX login handlers, cron, or
 * any custom wp_authenticate() call, whether or not REST_REQUEST /
 * XMLRPC_REQUEST are defined yet at that point.
 *
 * Exempt: an application password (core fires
 * `application_password_did_authenticate` from wp_authenticate_application_password,
 * and REST application passwords never reach `authenticate` at all), and
 * WP-CLI. While FailureThrottle blocks an account, every `authenticate` for it
 * is refused with the same message, right password or not, so the block does
 * not reveal whether a password was right.
 */
final class PasswordAuthGuard {

	/**
	 * `authenticate` priority: after the password checks (20) and the lockout check (30).
	 */
	public const PRIORITY = 99;

	/**
	 * Error code of a refusal.
	 */
	public const ERROR_CODE = 'lwfw_2fa_required';

	/**
	 * Error code while the account is throttled.
	 */
	public const THROTTLED_CODE = 'lwfw_2fa_throttled';

	/**
	 * Users an application password authenticated in this request.
	 *
	 * @var array<int, true>
	 */
	private array $app_password_users = array();

	/**
	 * Constructor.
	 *
	 * @param RequestContext|null  $context  Request kind; null = detect.
	 * @param SignonTracker|null   $signon   Shared sign-on state; null = none (refuse all password logins).
	 * @param FailureThrottle|null $throttle Per-account failure cap.
	 */
	public function __construct(
		private readonly ?RequestContext $context = null,
		private readonly ?SignonTracker $signon = null,
		private readonly ?FailureThrottle $throttle = null
	) {}

	/**
	 * Register the hooks.
	 *
	 * @param bool $block_app_passwords Whether two-factor users lose application passwords.
	 */
	public function register( bool $block_app_passwords ): void {
		add_filter( 'authenticate', array( $this, 'filter' ), self::PRIORITY, 3 );
		add_action( 'application_password_did_authenticate', array( $this, 'note_app_password' ), 10, 1 );

		if ( $block_app_passwords ) {
			add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'filter_app_passwords' ), 10, 2 );
		}
	}

	/**
	 * `authenticate` filter.
	 *
	 * @param mixed $user     WP_User, WP_Error or null from earlier callbacks.
	 * @param mixed $username Submitted login.
	 * @param mixed $password Submitted password (unused).
	 * @return mixed
	 */
	public function filter( $user, $username = '', $password = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$context = $this->context ?? new RequestContext();
		if ( $context->is( 'cli' ) ) {
			return $user;
		}

		$target = self::target( $user, $username );
		if ( null !== $target && $this->throttle()->is_blocked( (int) $target->ID ) && self::has_factors( $target ) ) {
			FailureLog::record( FailureLog::TWOFA_FAILED );
			return new WP_Error( self::THROTTLED_CODE, ChallengePage::throttled_message() );
		}

		if ( ! $user instanceof WP_User || isset( $this->app_password_users[ (int) $user->ID ] ) ) {
			return $user;
		}
		if ( ( null !== $this->signon && $this->signon->in_progress() && $context->is_interactive() ) || ! self::has_factors( $user ) ) {
			return $user;
		}

		return new WP_Error(
			self::ERROR_CODE,
			__( 'This account uses two-factor authentication, so its password alone cannot sign in here. Sign in on the login page, or use an application password where they are allowed.', 'lw-firewall' )
		);
	}

	/**
	 * Remember that an application password (not the account password) signed this user in.
	 *
	 * @param mixed $user User from `application_password_did_authenticate`.
	 */
	public function note_app_password( $user ): void {
		if ( $user instanceof WP_User ) {
			$this->app_password_users[ (int) $user->ID ] = true;
		}
	}

	/**
	 * `wp_is_application_passwords_available_for_user` filter.
	 *
	 * @param mixed $available Current answer.
	 * @param mixed $user      User.
	 */
	public function filter_app_passwords( $available, $user ): bool {
		if ( $user instanceof WP_User && self::has_factors( $user ) ) {
			return false;
		}

		return (bool) $available;
	}

	/**
	 * The account a sign-in is about: the authenticated user, or the one the
	 * submitted login names when the password check failed.
	 *
	 * @param mixed $user     Filter result.
	 * @param mixed $username Submitted login.
	 */
	private static function target( $user, $username ): ?WP_User {
		if ( $user instanceof WP_User ) {
			return $user;
		}
		if ( ! is_string( $username ) || '' === trim( $username ) ) {
			return null;
		}

		$found = get_user_by( 'login', trim( $username ) );
		if ( ! $found instanceof WP_User && is_email( trim( $username ) ) ) {
			$found = get_user_by( 'email', trim( $username ) );
		}

		return $found instanceof WP_User ? $found : null;
	}

	/**
	 * Whether the user enrolled a second factor.
	 *
	 * @param WP_User $user User.
	 */
	private static function has_factors( WP_User $user ): bool {
		return ( new UserFactors( (int) $user->ID ) )->has_any();
	}

	/**
	 * Failure cap.
	 */
	private function throttle(): FailureThrottle {
		return $this->throttle ?? new FailureThrottle();
	}
}
