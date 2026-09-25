<?php
/**
 * WordPress hooks for the per-username lockout.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\Logger;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageInterface;
use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Refuses a locked username at `authenticate` (after the password check, so
 * the answer is the same whether the password was right or not) and counts
 * failures at `wp_login_failed`. Requests from whitelisted IPs are neither
 * counted nor refused.
 */
final class UserLockGuard {

	/**
	 * `authenticate` priority: after core's password (20) checks.
	 */
	private const PRIORITY = 30;

	/**
	 * Error code of a refusal; LoginTracker skips failures carrying it.
	 */
	public const ERROR_CODE = 'lw_firewall_user_locked';

	/**
	 * Constructor.
	 *
	 * @param StorageInterface|null $storage Storage backend; the configured one when null.
	 */
	public function __construct( private ?StorageInterface $storage = null ) {
	}

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		$guard = new self();

		add_filter( 'authenticate', [ $guard, 'authenticate' ], self::PRIORITY, 2 );
		add_action( 'wp_login_failed', [ $guard, 'on_failed' ], 10, 1 );
	}

	/**
	 * Refuse a locked username.
	 *
	 * @param mixed $user     WP_User, WP_Error or null from earlier callbacks.
	 * @param mixed $username Submitted login.
	 * @return mixed
	 */
	public function authenticate( $user, $username ) {
		$login = LoginResolver::resolve( is_string( $username ) ? $username : '' );

		if ( '' === $login || ! self::should_refuse( $login, $this->lockout(), self::whitelisted() ) ) {
			return $user;
		}

		return new WP_Error(
			self::ERROR_CODE,
			__( 'Too many failed login attempts for this account. Try again later.', 'lw-firewall' )
		);
	}

	/**
	 * Whether a login must be refused, whatever the password check said.
	 *
	 * @param string      $login       Resolved login.
	 * @param UserLockout $lockout     Lockout bound to the active storage.
	 * @param bool        $whitelisted Whether the request comes from a whitelisted IP.
	 * @return bool
	 */
	public static function should_refuse( string $login, UserLockout $lockout, bool $whitelisted ): bool {
		return ! $whitelisted && $lockout->is_locked( $login );
	}

	/**
	 * Count a failed login for the submitted username.
	 *
	 * @param mixed $username Submitted login.
	 * @return void
	 */
	public function on_failed( $username ): void {
		$login = LoginResolver::resolve( is_string( $username ) ? $username : '' );

		if ( '' === $login || self::whitelisted() || ! $this->lockout()->record_failure( $login ) ) {
			return;
		}

		if ( ! empty( Options::get( 'log_enabled' ) ) ) {
			Logger::log(
				[
					'ip'     => IpDetector::get_ip(),
					'reason' => 'login_user_lockout',
					'ua'     => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 ),
					'url'    => sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ),
				]
			);
		}
	}

	/**
	 * Whether the current request comes from a whitelisted IP.
	 *
	 * @return bool
	 */
	private static function whitelisted(): bool {
		$whitelist = array_map( 'strval', (array) Options::get( 'ip_whitelist', [] ) );

		return [] !== $whitelist && IpMatcher::matches( IpDetector::get_ip(), $whitelist );
	}

	/**
	 * The lockout bound to the configured storage.
	 *
	 * @return UserLockout
	 */
	private function lockout(): UserLockout {
		return new UserLockout( $this->storage ?? lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) ) );
	}
}
