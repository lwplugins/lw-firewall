<?php
/**
 * Tracks the core wp_signon() call of the current request.
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
 * Only wp_signon() fires `wp_authenticate`. The window closes on `wp_login`,
 * on `wp_login_failed`, and at `authenticate` (last priority) whenever the
 * result is not a user, so it also closes on empty_username/empty_password,
 * which core does not report as failed logins. While open, the tracker knows
 * which username the sign-on is for (only a sign-on with both a login and a
 * password counts as a password sign-on), which "remember me" and secure-cookie values it uses (from
 * `secure_signon_cookie`, which receives the credentials), and, for a sign-on
 * with empty credentials (core's cookie re-auth on every wp-login.php load),
 * which user the browser's logged-in cookie already belongs to.
 */
final class SignonTracker {

	/**
	 * Whether a wp_signon() is running.
	 *
	 * @var bool
	 */
	private bool $active = false;

	/**
	 * Sanitized login of a password sign-on ('' = none, e.g. empty credentials).
	 *
	 * @var string
	 */
	private string $login = '';

	/**
	 * User of a valid logged-in cookie at an empty-credentials sign-on (0 = none).
	 *
	 * @var int
	 */
	private int $cookie_user = 0;

	/**
	 * Remember-me of the running sign-on (null = not seen).
	 *
	 * @var bool|null
	 */
	private ?bool $remember = null;

	/**
	 * Secure-cookie flag of the running sign-on (null = not seen).
	 *
	 * @var bool|null
	 */
	private ?bool $secure = null;

	/**
	 * Constructor.
	 *
	 * @param \Closure|null $cookie_user_reader Returns the user ID of a valid logged-in cookie (tests); null = wp_validate_auth_cookie().
	 */
	public function __construct( private readonly ?\Closure $cookie_user_reader = null ) {}

	/**
	 * Register the hooks.
	 */
	public function register(): void {
		// Last: plugins may rewrite the login by reference (e.g. email to username) first.
		add_action( 'wp_authenticate', array( $this, 'start' ), PHP_INT_MAX, 2 );
		add_filter( 'authenticate', array( $this, 'close_on_error' ), PHP_INT_MAX, 1 );
		add_filter( 'secure_signon_cookie', array( $this, 'capture' ), PHP_INT_MAX, 2 );
		add_action( 'wp_login', array( $this, 'finish' ), PHP_INT_MAX, 0 );
		add_action( 'wp_login_failed', array( $this, 'finish' ), PHP_INT_MAX, 0 );
	}

	/**
	 * `wp_authenticate`: a sign-on begins.
	 *
	 * @param mixed $user_login Submitted login.
	 * @param mixed $password   Submitted password.
	 */
	public function start( $user_login = '', $password = '' ): void {
		$login    = is_string( $user_login ) ? sanitize_user( $user_login ) : '';
		$has_pass = is_string( $password ) && '' !== trim( $password );

		$this->active      = true;
		$this->remember    = null;
		$this->secure      = null;
		$this->login       = '' !== $login && $has_pass ? $login : '';
		$this->cookie_user = empty( $user_login ) && empty( $password ) ? $this->read_cookie_user() : 0;
	}

	/**
	 * `authenticate` (last): close the window when the sign-on failed.
	 *
	 * @param mixed $user Result so far.
	 * @return mixed
	 */
	public function close_on_error( $user ) {
		if ( ! $user instanceof WP_User ) {
			$this->finish();
		}

		return $user;
	}

	/**
	 * Whether an `authenticate` result for this username belongs to the
	 * running password sign-on.
	 *
	 * @param mixed $username Username passed to `authenticate` (core sanitizes it the same way).
	 */
	public function accepts_password_for( $username ): bool {
		return $this->active && '' !== $this->login && is_string( $username ) && hash_equals( $this->login, $username );
	}

	/**
	 * `secure_signon_cookie`: note the sign-on's cookie settings (value unchanged).
	 *
	 * @param mixed $secure      Secure-cookie flag.
	 * @param mixed $credentials Sign-on credentials.
	 * @return mixed
	 */
	public function capture( $secure, $credentials = array() ) {
		if ( $this->active ) {
			$this->secure   = (bool) $secure;
			$this->remember = is_array( $credentials ) && ! empty( $credentials['remember'] );
		}

		return $secure;
	}

	/**
	 * `wp_login` / `wp_login_failed`: the sign-on is over.
	 */
	public function finish(): void {
		$this->active      = false;
		$this->login       = '';
		$this->cookie_user = 0;
		$this->remember    = null;
		$this->secure      = null;
	}

	/**
	 * Whether a wp_signon() is running.
	 */
	public function in_progress(): bool {
		return $this->active;
	}

	/**
	 * User who was already signed in by cookie at an empty-credentials sign-on.
	 */
	public function cookie_user(): int {
		return $this->active ? $this->cookie_user : 0;
	}

	/**
	 * Remember-me of the running sign-on, null when not seen.
	 */
	public function remember(): ?bool {
		return $this->remember;
	}

	/**
	 * Secure-cookie flag of the running sign-on, null when not seen.
	 */
	public function secure(): ?bool {
		return $this->secure;
	}

	/**
	 * User ID of the browser's valid logged-in cookie, 0 when none.
	 */
	private function read_cookie_user(): int {
		if ( null !== $this->cookie_user_reader ) {
			return (int) ( $this->cookie_user_reader )();
		}

		return (int) wp_validate_auth_cookie( '', 'logged_in' );
	}
}
