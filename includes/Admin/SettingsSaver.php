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

	use InputParserTrait;

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

		$values['enabled']          = ! empty( $post_data['enabled'] );
		$values['log_enabled']      = ! empty( $post_data['log_enabled'] );
		$values['protect_cron']     = ! empty( $post_data['protect_cron'] );
		$values['protect_xmlrpc']   = ! empty( $post_data['protect_xmlrpc'] );
		$values['protect_login']    = ! empty( $post_data['protect_login'] );
		$values['protect_rest_api'] = ! empty( $post_data['protect_rest_api'] );
		$values['protect_404']      = ! empty( $post_data['protect_404'] );
		$values['auto_ban_enabled'] = ! empty( $post_data['auto_ban_enabled'] );
		$values['security_headers'] = ! empty( $post_data['security_headers'] );
		$values['geo_enabled']      = ! empty( $post_data['geo_enabled'] );

		$values['storage'] = isset( $post_data['storage'] )
			? sanitize_key( $post_data['storage'] )
			: $current['storage'];

		$values['rate_limit'] = isset( $post_data['rate_limit'] )
			? absint( $post_data['rate_limit'] )
			: $current['rate_limit'];

		$values['rate_window'] = isset( $post_data['rate_window'] )
			? absint( $post_data['rate_window'] )
			: $current['rate_window'];

		$values['auto_ban_threshold'] = isset( $post_data['auto_ban_threshold'] )
			? absint( $post_data['auto_ban_threshold'] )
			: $current['auto_ban_threshold'];

		$values['auto_ban_duration'] = isset( $post_data['auto_ban_duration'] )
			? absint( $post_data['auto_ban_duration'] )
			: $current['auto_ban_duration'];

		$values['action'] = isset( $post_data['action'] )
			? sanitize_key( $post_data['action'] )
			: $current['action'];

		$values['geo_action'] = isset( $post_data['geo_action'] )
			? sanitize_key( $post_data['geo_action'] )
			: $current['geo_action'];

		$values['filter_params']     = self::parse_filter_params( $post_data );
		$values['blocked_bots']      = self::parse_blocked_bots( $post_data );
		$values['ip_whitelist']      = self::parse_lines( $post_data, 'ip_whitelist' );
		$values['ip_blacklist']      = self::parse_lines( $post_data, 'ip_blacklist' );
		$values['blocked_countries'] = self::parse_country_codes( $post_data );

		Options::save( $values );

		\LightweightPlugins\Firewall\Geo\HtaccessWriter::sync();
	}

	/**
	 * Handle special actions (worker reinstall, clear log, geo update).
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

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_save().
		if ( ! empty( $_POST['lw_firewall_geo_update'] ) ) {
			$options   = Options::get_all();
			$countries = (array) ( $options['blocked_countries'] ?? [] );

			if ( ! empty( $countries ) ) {
				\LightweightPlugins\Firewall\Geo\CidrUpdater::update( $countries );
			}
		}
	}
}
