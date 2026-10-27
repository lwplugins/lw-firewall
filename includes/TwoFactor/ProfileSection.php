<?php
/**
 * The two-factor section of the user profile screens.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\Admin\BuildAssets;
use LightweightPlugins\Firewall\TwoFactor\Passkey\WebAuthnFactory;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Prints the mount point (EnrollmentNotice::PROFILE_ANCHOR) with a loading
 * placeholder; build/profile.js renders the section from the REST routes
 * (FactorsController, PasskeysController). On profile.php the user manages
 * their own factors; on user-edit.php (another user) only the status and the
 * "Reset two-factor" action appear.
 */
final class ProfileSection {

	public const HANDLE = 'lw-firewall-profile';

	/**
	 * Hook the section and its assets.
	 */
	public function register(): void {
		add_action( 'show_user_profile', array( $this, 'render' ) );
		add_action( 'edit_user_profile', array( $this, 'render' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
	}

	/**
	 * Enqueue the profile entry and the QR script on the two profile screens.
	 *
	 * @param string $hook_suffix Admin page.
	 */
	public function enqueue( string $hook_suffix ): void {
		if ( ! in_array( $hook_suffix, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}

		QrScript::enqueue();
		if ( BuildAssets::enqueue( 'profile', self::HANDLE ) ) {
			wp_enqueue_style( 'wp-components' );
		}
	}

	/**
	 * Print the section.
	 *
	 * @param WP_User $user Profile being shown.
	 */
	public function render( WP_User $user ): void {
		$self = get_current_user_id() === (int) $user->ID;
		if ( ! $self && ! current_user_can( 'edit_user', (int) $user->ID ) ) {
			return;
		}

		$config = array(
			'userId'   => (int) $user->ID,
			'self'     => $self,
			'passkeys' => $self && WebAuthnFactory::available(),
		);
		?>
		<h2><?php esc_html_e( 'Two-factor authentication', 'lw-firewall' ); ?></h2>
		<div id="<?php echo esc_attr( EnrollmentNotice::PROFILE_ANCHOR ); ?>" class="lwfw-2fa-profile" data-config="<?php echo esc_attr( (string) wp_json_encode( $config ) ); ?>">
			<div class="lwfw-2fa-placeholder" role="status" aria-busy="true">
				<span class="screen-reader-text"><?php esc_html_e( 'Loading…', 'lw-firewall' ); ?></span>
				<span class="lwfw-2fa-placeholder__line" aria-hidden="true"></span>
				<span class="lwfw-2fa-placeholder__line is-short" aria-hidden="true"></span>
			</div>
			<noscript><p><?php esc_html_e( 'Two-factor settings need JavaScript.', 'lw-firewall' ); ?></p></noscript>
		</div>
		<?php
	}
}
