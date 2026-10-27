<?php
/**
 * Drops remembered devices when the account's sign-in secrets change.
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
 * A remembered device is trusted for the factors and the password the account
 * had when it was issued. Any factor change or password change rotates the
 * remember salt, so a stolen cookie or a stolen-then-reset account cannot
 * keep skipping the second factor.
 */
final class RememberRevoker {

	/**
	 * Register the listeners.
	 */
	public function register(): void {
		add_action( UserFactors::CHANGED_ACTION, array( $this, 'on_factor_changed' ), 5, 1 );
		add_action( 'wp_set_password', array( $this, 'on_set_password' ), 10, 2 );
		add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 1 );
		add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 2 );
	}

	/**
	 * A factor was added or removed.
	 *
	 * @param mixed $user_id User.
	 */
	public function on_factor_changed( $user_id ): void {
		$this->forget( $user_id );
	}

	/**
	 * Core stored a new password hash (wp_set_password(), wp_update_user(), reset_password()).
	 *
	 * @param mixed $password Plain password (unused).
	 * @param mixed $user_id  User.
	 */
	public function on_set_password( $password, $user_id = 0 ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		$this->forget( $user_id );
	}

	/**
	 * A password reset finished.
	 *
	 * @param mixed $user User.
	 */
	public function on_password_reset( $user ): void {
		if ( $user instanceof WP_User ) {
			$this->forget( $user->ID );
		}
	}

	/**
	 * A profile was saved: forget the devices when the password hash differs.
	 *
	 * @param mixed $user_id       User.
	 * @param mixed $old_user_data Previous WP_User.
	 */
	public function on_profile_update( $user_id, $old_user_data = null ): void {
		$now = is_numeric( $user_id ) ? get_userdata( (int) $user_id ) : false;
		if ( $now instanceof WP_User && $old_user_data instanceof WP_User && $now->user_pass !== $old_user_data->user_pass ) {
			$this->forget( $user_id );
		}
	}

	/**
	 * Rotate the salt of a user.
	 *
	 * @param mixed $user_id User.
	 */
	private function forget( $user_id ): void {
		if ( is_numeric( $user_id ) && (int) $user_id > 0 ) {
			( new UserFactors( (int) $user_id ) )->forget_devices();
		}
	}
}
