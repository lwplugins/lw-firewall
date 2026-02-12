<?php
/**
 * Settings Saver class.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin;

use LightweightPlugins\Firewall\Activator;
use LightweightPlugins\Firewall\Logger;
use LightweightPlugins\Firewall\Options;

/**
 * Handles saving settings form data.
 */
final class SettingsSaver {

	/**
	 * Handle form submission.
	 *
	 * @return void
	 */
	public static function maybe_save(): void {
		if ( ! isset( $_POST['lw_firewall_save'] ) ) {
			return;
		}

		if (
			! isset( $_POST['_lw_firewall_nonce'] )
			|| ! wp_verify_nonce( sanitize_key( $_POST['_lw_firewall_nonce'] ), 'lw_firewall_save' )
		) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		self::save_options();
		self::handle_actions();

		$active_tab = isset( $_POST['lw_firewall_active_tab'] )
			? sanitize_key( $_POST['lw_firewall_active_tab'] )
			: '';

		wp_safe_redirect(
			add_query_arg(
				[
					'page'    => SettingsPage::SLUG,
					'updated' => '1',
				],
				admin_url( 'admin.php' )
			) . ( $active_tab ? '#' . $active_tab : '' )
		);
		exit;
	}

	/**
	 * Save main options.
	 *
	 * @return void
	 */
	private static function save_options(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_save().
		$post_data = isset( $_POST['lw_firewall_options'] )
			? wp_unslash( (array) $_POST['lw_firewall_options'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Missing
			: [];

		$current = Options::get_all();
		$values  = [];

		$values['enabled']     = ! empty( $post_data['enabled'] );
		$values['log_enabled'] = ! empty( $post_data['log_enabled'] );

		$values['storage'] = isset( $post_data['storage'] )
			? sanitize_key( $post_data['storage'] )
			: $current['storage'];

		$values['rate_limit'] = isset( $post_data['rate_limit'] )
			? absint( $post_data['rate_limit'] )
			: $current['rate_limit'];

		$values['rate_window'] = isset( $post_data['rate_window'] )
			? absint( $post_data['rate_window'] )
			: $current['rate_window'];

		$values['action'] = isset( $post_data['action'] )
			? sanitize_key( $post_data['action'] )
			: $current['action'];

		$values['filter_params'] = self::parse_filter_params( $post_data );
		$values['blocked_bots']  = self::parse_blocked_bots( $post_data );

		Options::save( $values );
	}

	/**
	 * Parse filter params from textarea input.
	 *
	 * @param array<string, mixed> $post_data Form data.
	 * @return array<int, string>
	 */
	private static function parse_filter_params( array $post_data ): array {
		if ( empty( $post_data['filter_params'] ) ) {
			return [ 'filter_', 'query_type_' ];
		}

		$raw   = sanitize_textarea_field( (string) $post_data['filter_params'] );
		$lines = array_filter( array_map( 'trim', explode( "\n", $raw ) ) );

		return array_values( $lines );
	}

	/**
	 * Parse blocked bots from textarea input.
	 *
	 * @param array<string, mixed> $post_data Form data.
	 * @return array<int, string>
	 */
	private static function parse_blocked_bots( array $post_data ): array {
		if ( ! isset( $post_data['blocked_bots'] ) ) {
			return Options::get( 'blocked_bots' );
		}

		$raw   = sanitize_textarea_field( (string) $post_data['blocked_bots'] );
		$lines = array_filter( array_map( 'trim', explode( "\n", $raw ) ) );

		return array_values( $lines );
	}

	/**
	 * Handle special actions (worker reinstall, clear log).
	 *
	 * @return void
	 */
	private static function handle_actions(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_save().
		if ( ! empty( $_POST['lw_firewall_reinstall_worker'] ) ) {
			Activator::install_worker();
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_save().
		if ( ! empty( $_POST['lw_firewall_clear_log'] ) ) {
			Logger::clear();
		}
	}
}
