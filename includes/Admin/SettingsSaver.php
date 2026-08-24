<?php
/**
 * Settings Saver class.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin;

use LightweightPlugins\Firewall\Activator;
use LightweightPlugins\Firewall\Alerts\AdminBaseline;
use LightweightPlugins\Firewall\Alerts\AdminMonitor;
use LightweightPlugins\Firewall\Alerts\AlertMailer;
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
		$notice = self::handle_actions();

		$active_tab = isset( $_POST['lw_firewall_active_tab'] )
			? sanitize_key( $_POST['lw_firewall_active_tab'] )
			: '';

		$query = [
			'page'    => SettingsPage::SLUG,
			'updated' => '1',
		];

		if ( '' !== $notice ) {
			$query['lw_notice'] = $notice;
		}

		wp_safe_redirect(
			add_query_arg( $query, admin_url( 'admin.php' ) ) . ( $active_tab ? '#' . $active_tab : '' )
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

		$values['enabled']             = ! empty( $post_data['enabled'] );
		$values['log_enabled']         = ! empty( $post_data['log_enabled'] );
		$values['protect_cron']        = ! empty( $post_data['protect_cron'] );
		$values['protect_xmlrpc']      = ! empty( $post_data['protect_xmlrpc'] );
		$values['protect_login']       = ! empty( $post_data['protect_login'] );
		$values['protect_rest_api']    = ! empty( $post_data['protect_rest_api'] );
		$values['protect_404']         = ! empty( $post_data['protect_404'] );
		$values['auto_ban_enabled']    = ! empty( $post_data['auto_ban_enabled'] );
		$values['login_limit_enabled'] = ! empty( $post_data['login_limit_enabled'] );
		$values['security_headers']    = ! empty( $post_data['security_headers'] );

		$values['admin_alert_enabled']      = ! empty( $post_data['admin_alert_enabled'] );
		$values['admin_alert_scan_enabled'] = ! empty( $post_data['admin_alert_scan_enabled'] );
		$values['admin_alert_changes']      = ! empty( $post_data['admin_alert_changes'] );
		$values['admin_alert_email']        = isset( $post_data['admin_alert_email'] )
			? self::parse_email_list( (string) $post_data['admin_alert_email'] )
			: $current['admin_alert_email'];
		$values['geo_enabled']              = ! empty( $post_data['geo_enabled'] );

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

		$values['login_max_attempts'] = isset( $post_data['login_max_attempts'] )
			? absint( $post_data['login_max_attempts'] )
			: $current['login_max_attempts'];

		$values['login_lockout_window'] = isset( $post_data['login_lockout_window'] )
			? absint( $post_data['login_lockout_window'] )
			: $current['login_lockout_window'];

		$values['login_lockout_duration'] = isset( $post_data['login_lockout_duration'] )
			? absint( $post_data['login_lockout_duration'] )
			: $current['login_lockout_duration'];

		$values['register_protect_enabled'] = ! empty( $post_data['register_protect_enabled'] );
		$values['register_honeypot']        = ! empty( $post_data['register_honeypot'] );
		$values['register_single_use']      = ! empty( $post_data['register_single_use'] );

		$values['register_min_fill_time'] = isset( $post_data['register_min_fill_time'] )
			? absint( $post_data['register_min_fill_time'] )
			: $current['register_min_fill_time'];

		$values['register_token_max_age'] = isset( $post_data['register_token_max_age'] )
			? absint( $post_data['register_token_max_age'] )
			: $current['register_token_max_age'];

		$values['register_ban_threshold'] = isset( $post_data['register_ban_threshold'] )
			? absint( $post_data['register_ban_threshold'] )
			: $current['register_ban_threshold'];

		$values['register_ban_duration'] = isset( $post_data['register_ban_duration'] )
			? absint( $post_data['register_ban_duration'] )
			: $current['register_ban_duration'];

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

		// Turning alerts on must not mail about the administrators the site
		// already had — snapshot them silently so only later arrivals alert.
		if ( empty( $current['admin_alert_enabled'] ) && ! empty( $values['admin_alert_enabled'] ) && ! AdminBaseline::is_seeded() ) {
			AdminBaseline::seed();
		}

		\LightweightPlugins\Firewall\Geo\HtaccessWriter::sync();
	}

	/**
	 * Reduce a raw recipient string to a comma-separated list of valid addresses.
	 *
	 * @param string $raw Raw field value.
	 * @return string
	 */
	private static function parse_email_list( string $raw ): string {
		$parts = preg_split( '/[\r\n,;]+/', $raw );
		$clean = [];

		foreach ( is_array( $parts ) ? $parts : [] as $part ) {
			$email = sanitize_email( trim( (string) $part ) );

			if ( '' !== $email && is_email( $email ) ) {
				$clean[] = $email;
			}
		}

		return implode( ', ', array_unique( $clean ) );
	}

	/**
	 * Handle special actions (worker reinstall, clear log, geo update, alerts).
	 *
	 * @return string Notice key to surface after the redirect, or '' for none.
	 */
	private static function handle_actions(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_save().
		if ( ! empty( $_POST['lw_firewall_reinstall_worker'] ) ) {
			Activator::install_worker();
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_save().
		if ( ! empty( $_POST['lw_firewall_clear_log'] ) ) {
			Logger::clear();
		}

		// The Alerts tab buttons submit through the shared save button with a
		// distinct value, so a click saves the form and then runs the action.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_save().
		$action = isset( $_POST['lw_firewall_save'] ) ? sanitize_key( wp_unslash( $_POST['lw_firewall_save'] ) ) : '';

		$notice = '';

		if ( 'admin_scan' === $action ) {
			$found  = AdminMonitor::run_scan();
			$clean  = empty( $found['new'] ) && empty( $found['changes'] );
			$notice = $clean ? 'scan_clean' : 'scan_found';
		}

		if ( 'admin_alert_test' === $action ) {
			$notice = AlertMailer::send_test() ? 'test_sent' : 'test_failed';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in maybe_save().
		if ( ! empty( $_POST['lw_firewall_geo_update'] ) ) {
			$options   = Options::get_all();
			$countries = (array) ( $options['blocked_countries'] ?? [] );

			if ( ! empty( $countries ) ) {
				\LightweightPlugins\Firewall\Geo\CidrUpdater::update( $countries );
			}
		}

		return $notice;
	}
}
