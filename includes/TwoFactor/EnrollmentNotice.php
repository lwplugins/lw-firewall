<?php
/**
 * Admin reminder to set up two-factor login during the grace period.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shown on `admin_notices` (not the network admin) to the current user only,
 * while they are required, have no factor and are inside the grace. After
 * the grace the login screen takes over (forced enrollment).
 */
final class EnrollmentNotice {

	/**
	 * Anchor of the two-factor section on the profile screen.
	 */
	public const PROFILE_ANCHOR = 'lw-firewall-2fa';

	/**
	 * Constructor.
	 *
	 * @param Enforcement|null $enforcement Enforcement rules; null = default.
	 */
	public function __construct( private readonly ?Enforcement $enforcement = null ) {}

	/**
	 * Register the hook.
	 */
	public function register(): void {
		add_action( 'admin_notices', array( $this, 'render' ) );
	}

	/**
	 * Print the notice for the current user, when it applies.
	 */
	public function render(): void {
		$user = wp_get_current_user();
		if ( (int) $user->ID <= 0 ) {
			return;
		}

		$enforcement = $this->enforcement ?? new Enforcement();
		if ( ! $enforcement->in_grace( $user ) ) {
			return;
		}

		$days = max( 1, $enforcement->days_left( $user ) );
		?>
		<div class="notice notice-warning lw-notice">
			<p>
				<span class="dashicons dashicons-lock" aria-hidden="true"></span>
				<?php
				/* translators: %d: number of days */
				echo esc_html( sprintf( _n( 'Set up two-factor login within %d day.', 'Set up two-factor login within %d days.', $days, 'lw-firewall' ), $days ) );
				?>
				<a href="<?php echo esc_url( admin_url( 'profile.php#' . self::PROFILE_ANCHOR ) ); ?>"><?php esc_html_e( 'Set it up now', 'lw-firewall' ); ?></a>
			</p>
		</div>
		<?php
	}
}
