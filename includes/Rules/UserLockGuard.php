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
	 * Register the hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_filter( 'authenticate', [ self::class, 'authenticate' ], self::PRIORITY, 2 );
		add_action( 'wp_login_failed', [ self::class, 'on_failed' ], 10, 1 );
	}

	/**
	 * Refuse a locked username.
	 *
	 * @param mixed $user     WP_User, WP_Error or null from earlier callbacks.
	 * @param mixed $username Submitted login.
	 * @return mixed
	 */
	public static function authenticate( $user, $username ) {
		$login = self::resolve( is_string( $username ) ? $username : '' );

		if ( '' === $login || ! self::should_refuse( $login, self::lockout(), self::whitelisted() ) ) {
			return $user;
		}

		return new WP_Error(
			'lw_firewall_user_locked',
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
	public static function on_failed( $username ): void {
		$login = self::resolve( is_string( $username ) ? $username : '' );

		if ( '' === $login || self::whitelisted() || ! self::lockout()->record_failure( $login ) ) {
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
	 * The account a login refers to: an email address that belongs to a user
	 * resolves to that user's login, so both spellings share one counter.
	 *
	 * @param string $username Submitted login.
	 * @return string
	 */
	private static function resolve( string $username ): string {
		$username = trim( $username );

		if ( '' !== $username && is_email( $username ) ) {
			$user = get_user_by( 'email', $username );

			if ( $user ) {
				return (string) $user->user_login;
			}
		}

		return $username;
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
	private static function lockout(): UserLockout {
		return new UserLockout( lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) ) );
	}
}
