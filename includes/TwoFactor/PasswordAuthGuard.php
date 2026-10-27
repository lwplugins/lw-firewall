<?php
/**
 * Refuses password-only sign-ins of two-factor users where no challenge page exists.
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
 * XML-RPC, REST (with a password-auth plugin), AJAX login handlers and cron
 * cannot show the second-factor page, so for a two-factor user the password
 * alone is refused there. Application passwords stay usable (they are a
 * separate, revocable credential) unless `twofa_block_app_passwords` is on.
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
	 * Users an application password authenticated in this request.
	 *
	 * @var array<int, true>
	 */
	private array $app_password_users = array();

	/**
	 * Constructor.
	 *
	 * @param RequestContext|null $context Request kind; null = detect.
	 */
	public function __construct( private readonly ?RequestContext $context = null ) {}

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
	 * @param mixed $username Submitted login (unused).
	 * @param mixed $password Submitted password (unused).
	 * @return mixed
	 */
	public function filter( $user, $username = '', $password = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( ! $user instanceof WP_User || isset( $this->app_password_users[ (int) $user->ID ] ) ) {
			return $user;
		}
		if ( ! $this->context()->refuses_passwords() || ! ( new UserFactors( (int) $user->ID ) )->has_any() ) {
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
		if ( $user instanceof WP_User && ( new UserFactors( (int) $user->ID ) )->has_any() ) {
			return false;
		}

		return (bool) $available;
	}

	/**
	 * Request kind.
	 */
	private function context(): RequestContext {
		return $this->context ?? new RequestContext();
	}
}
