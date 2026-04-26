<?php
/**
 * Worker status admin notice.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin;

use LightweightPlugins\Firewall\Activator;

/**
 * Renders an actionable notice when the MU-plugin worker is missing or stale.
 *
 * The notice carries the `lw-notice` class so the LW pages NoticeManager does
 * not hide it on the plugin's own settings screens.
 */
final class WorkerNotice {

	/**
	 * Error code → human reason (last install attempt).
	 *
	 * @return array<string, string>
	 */
	private static function reasons(): array {
		return [
			'source_missing'       => __( 'The worker source file inside the plugin is missing.', 'lw-firewall' ),
			'mu_dir_create_failed' => __( 'The mu-plugins directory could not be created.', 'lw-firewall' ),
			'mu_dir_not_writable'  => __( 'The mu-plugins directory is not writable.', 'lw-firewall' ),
			'copy_failed'          => __( 'Copying the worker file failed (disk full or permission denied).', 'lw-firewall' ),
		];
	}

	/**
	 * Render the notice.
	 *
	 * @return void
	 */
	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$installed = Activator::is_worker_installed();
		$attempt   = Activator::get_last_attempt();
		$writable  = Activator::is_mu_dir_writable();
		$mu_dir    = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '';

		?>
		<div class="notice notice-error lw-notice">
			<p><strong><?php esc_html_e( 'LW Firewall — protection is OFF', 'lw-firewall' ); ?></strong></p>
			<p>
				<?php
				echo esc_html(
					$installed
						? __( 'The MU-plugin worker is installed but its version does not match this plugin. Runtime protection is disabled until it is reinstalled.', 'lw-firewall' )
						: __( 'The MU-plugin worker file is missing from mu-plugins/. Runtime protection is disabled until it is reinstalled.', 'lw-firewall' )
				);
				?>
			</p>
			<?php self::render_reason( $attempt ); ?>
			<?php self::render_hints( $writable, $mu_dir ); ?>
			<p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=lw-firewall#status' ) ); ?>" class="button button-primary">
					<?php esc_html_e( 'Open Status tab', 'lw-firewall' ); ?>
				</a>
			</p>
		</div>
		<?php
	}

	/**
	 * Show the last install attempt outcome, if known.
	 *
	 * @param array{success: bool, error: string, time: int}|null $attempt Last attempt.
	 * @return void
	 */
	private static function render_reason( ?array $attempt ): void {
		if ( null === $attempt || true === $attempt['success'] ) {
			return;
		}

		$reasons = self::reasons();
		$message = $reasons[ $attempt['error'] ] ?? __( 'Unknown install error.', 'lw-firewall' );

		echo '<p><em>';
		printf(
			/* translators: 1: reason text, 2: human-readable time difference */
			esc_html__( 'Last install attempt failed: %1$s (%2$s ago)', 'lw-firewall' ),
			esc_html( $message ),
			esc_html( human_time_diff( $attempt['time'] ) )
		);
		echo '</em></p>';
	}

	/**
	 * Show actionable hints based on the environment.
	 *
	 * @param bool   $writable Whether mu-plugins is writable.
	 * @param string $mu_dir   mu-plugins directory path.
	 * @return void
	 */
	private static function render_hints( bool $writable, string $mu_dir ): void {
		if ( ! $writable && '' !== $mu_dir ) {
			echo '<p>';
			printf(
				/* translators: %s: mu-plugins directory path */
				esc_html__( 'Make %s writable by the web server, then re-save the firewall settings.', 'lw-firewall' ),
				'<code>' . esc_html( $mu_dir ) . '</code>'
			);
			echo '</p>';
			return;
		}

		echo '<p>';
		esc_html_e( 'A security plugin or hosting cleanup may be removing the worker. Check the Status tab for the last install attempt and reinstall from there.', 'lw-firewall' );
		echo '</p>';
	}
}
