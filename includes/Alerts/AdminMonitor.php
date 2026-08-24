<?php
/**
 * Administrator creation and takeover monitoring.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Alerts;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Watches for accounts gaining administrator privileges — and for existing
 * administrators being modified — then mails an alert.
 *
 * Two independent detection paths, because no single one is complete:
 *
 * 1. Core hooks catch anything that goes through the WordPress user API —
 *    the admin UI, REST, WP-CLI, and any plugin or custom code calling
 *    wp_insert_user() / set_role() / wp_update_user() / wp_set_password().
 * 2. A scheduled reconciliation scan diffs the live administrator list
 *    against a stored baseline, which is the only way to see changes made by
 *    a direct database write, by code that bypasses core APIs, or while this
 *    plugin was inactive.
 *
 * The baseline de-duplicates across both paths, so one event produces at most
 * one alert.
 */
final class AdminMonitor {

	/**
	 * Cron hook for the reconciliation scan.
	 */
	public const CRON_HOOK = 'lw_firewall_admin_scan';

	/**
	 * Register hooks. Called unconditionally at bootstrap.
	 *
	 * Deliberately independent of the firewall's master `enabled` switch and
	 * of the MU-worker health check: this is passive monitoring, and it must
	 * keep watching even when the request-filtering runtime is off.
	 *
	 * @return void
	 */
	public static function init(): void {
		if ( empty( Options::get( 'admin_alert_enabled' ) ) ) {
			self::unschedule_scan();
			return;
		}

		add_action( 'user_register', [ self::class, 'on_user_register' ], 10, 1 );
		add_action( 'set_user_role', [ self::class, 'on_set_user_role' ], 10, 1 );
		add_action( 'add_user_role', [ self::class, 'on_add_user_role' ], 10, 1 );
		add_action( 'granted_super_admin', [ self::class, 'on_granted_super_admin' ], 10, 1 );
		add_action( 'add_user_to_blog', [ self::class, 'on_add_user_to_blog' ], 10, 1 );

		if ( ! empty( Options::get( 'admin_alert_changes' ) ) ) {
			add_action( 'profile_update', [ self::class, 'on_profile_update' ], 10, 1 );
			add_action( 'wp_set_password', [ self::class, 'on_set_password' ], 10, 2 );
		}

		add_action( self::CRON_HOOK, [ self::class, 'run_scheduled_scan' ] );

		self::maybe_seed_baseline();

		if ( empty( Options::get( 'admin_alert_scan_enabled' ) ) ) {
			self::unschedule_scan();
			return;
		}

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}
	}

	/**
	 * Handle a freshly registered user.
	 *
	 * @param int $user_id New user ID.
	 * @return void
	 */
	public static function on_user_register( $user_id ): void {
		self::evaluate( (int) $user_id, 'user_register' );
	}

	/**
	 * Handle a role replacement.
	 *
	 * @param int $user_id Affected user ID.
	 * @return void
	 */
	public static function on_set_user_role( $user_id ): void {
		self::evaluate( (int) $user_id, 'set_user_role' );
	}

	/**
	 * Handle an additional role being granted.
	 *
	 * @param int $user_id Affected user ID.
	 * @return void
	 */
	public static function on_add_user_role( $user_id ): void {
		self::evaluate( (int) $user_id, 'add_user_role' );
	}

	/**
	 * Handle a multisite super admin grant.
	 *
	 * @param int $user_id Affected user ID.
	 * @return void
	 */
	public static function on_granted_super_admin( $user_id ): void {
		self::evaluate( (int) $user_id, 'granted_super_admin' );
	}

	/**
	 * Handle a user being added to a site on multisite.
	 *
	 * @param int $user_id Affected user ID.
	 * @return void
	 */
	public static function on_add_user_to_blog( $user_id ): void {
		self::evaluate( (int) $user_id, 'add_user_to_blog' );
	}

	/**
	 * Handle a profile update (email, username, password via wp_update_user).
	 *
	 * @param int $user_id Affected user ID.
	 * @return void
	 */
	public static function on_profile_update( $user_id ): void {
		self::evaluate( (int) $user_id, 'profile_update' );
	}

	/**
	 * Handle a direct password set or reset.
	 *
	 * The first hook argument is the plaintext password; it is accepted and
	 * immediately discarded so it can never reach a log, an option or an email.
	 *
	 * @param string $password Plaintext password (discarded).
	 * @param int    $user_id  Affected user ID.
	 * @return void
	 */
	public static function on_set_password( $password, $user_id ): void {
		unset( $password );

		self::evaluate( (int) $user_id, 'wp_set_password' );
	}

	/**
	 * Cron callback wrapper around the scan.
	 *
	 * Kept separate from run_scan() so the action callback returns nothing
	 * while the CLI and admin callers still get the findings back.
	 *
	 * @return void
	 */
	public static function run_scheduled_scan(): void {
		AdminScanner::run();
	}

	/**
	 * Reconcile the live administrator list against the stored baseline.
	 *
	 * @return array{new: array<int, int>, changes: array<int, array{id: int, field: string, from: string, to: string}>}
	 */
	public static function run_scan(): array {
		return AdminScanner::run();
	}

	/**
	 * Timestamp of the next scheduled scan (0 when not scheduled).
	 *
	 * @return int
	 */
	public static function next_scan(): int {
		return (int) wp_next_scheduled( self::CRON_HOOK );
	}

	/**
	 * Decide whether a user event warrants an alert, then send one.
	 *
	 * Never trusts the hook alone: the account must actually hold
	 * administrator privileges right now, and the alert is chosen by comparing
	 * against the baseline — a brand-new administrator gets the "new account"
	 * alert, a known one gets the "account modified" alert, and an event that
	 * changed nothing we track gets nothing.
	 *
	 * @param int    $user_id Affected user ID.
	 * @param string $source  Detection source key.
	 * @return void
	 */
	private static function evaluate( int $user_id, string $source ): void {
		if ( $user_id <= 0 ) {
			return;
		}

		// Before the first snapshot exists, record instead of alerting —
		// otherwise a site upgrading into this feature would be mailed about
		// every administrator it already had.
		if ( ! AdminBaseline::is_seeded() ) {
			AdminBaseline::seed();
			return;
		}

		if ( ! AdminDetector::is_admin_user( $user_id ) ) {
			return;
		}

		if ( ! AdminBaseline::knows( $user_id ) ) {
			AdminBaseline::remember( $user_id );
			AlertMailer::notify( [ $user_id ], $source );
			return;
		}

		self::evaluate_identity( $user_id, $source );
	}

	/**
	 * Alert on identity changes to an administrator we already knew about.
	 *
	 * @param int    $user_id Affected user ID.
	 * @param string $source  Detection source key.
	 * @return void
	 */
	private static function evaluate_identity( int $user_id, string $source ): void {
		if ( empty( Options::get( 'admin_alert_changes' ) ) ) {
			return;
		}

		$profile = AdminDetector::profile( $user_id );

		if ( null === $profile ) {
			return;
		}

		$known   = AdminBaseline::get_profiles();
		$changes = BaselineDiff::profiles(
			isset( $known[ $user_id ] ) ? [ $user_id => $known[ $user_id ] ] : [],
			[ $user_id => $profile ]
		);

		// Always refresh the stored fingerprint, including when nothing we
		// track changed — that is how an entry recorded before this feature
		// existed gets filled in without raising a phantom alert.
		AdminBaseline::remember( $user_id );

		if ( ! empty( $changes ) ) {
			AlertMailer::notify_changes( $changes, $source );
		}
	}

	/**
	 * Take the first snapshot if the feature was switched on out of band.
	 *
	 * The settings form and plugin activation seed explicitly; this covers
	 * `wp lw-firewall config set admin_alert_enabled true` and a wp-config.php
	 * constant, so alerting starts from a known-good state either way.
	 *
	 * Restricted to admin, cron and CLI requests so front-end page loads never
	 * pay for the check.
	 *
	 * @return void
	 */
	private static function maybe_seed_baseline(): void {
		$is_cli = defined( 'WP_CLI' ) && WP_CLI;

		if ( ! is_admin() && ! wp_doing_cron() && ! $is_cli ) {
			return;
		}

		if ( ! AdminBaseline::is_seeded() ) {
			AdminBaseline::seed();
		}
	}

	/**
	 * Remove the scan cron event if one is scheduled.
	 *
	 * @return void
	 */
	private static function unschedule_scan(): void {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );

		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
	}
}
