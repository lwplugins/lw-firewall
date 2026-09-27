<?php
/**
 * Comment and product review spam guard.
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
 * Refuses bot comments before they are stored.
 *
 * Two hooks, because neither alone is right:
 * - `pre_comment_on_post` fires only inside wp_handle_comment_submission(),
 *   i.e. for comment-form POSTs (wp-comments-post.php, and AJAX comment
 *   plugins that reuse it). It marks the request; REST, XML-RPC and admin
 *   replies never render the form and are left alone.
 * - `pre_comment_approved` runs after core's own validation (required
 *   fields, duplicates, flood) and before the insert, and a WP_Error returned
 *   there aborts the comment. Judging here means a submission that core
 *   would have refused anyway never counts toward a ban.
 */
final class CommentGuard {

	/**
	 * Post ID of the comment-form submission in this request, 0 when none.
	 *
	 * @var int
	 */
	private static int $submission = 0;

	/**
	 * Register the guard's hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		CommentFields::init();

		add_action( 'pre_comment_on_post', [ self::class, 'mark_submission' ] );
		add_filter( 'pre_comment_approved', [ self::class, 'filter_approved' ], 99, 2 );
	}

	/**
	 * Remember that this request is a comment-form submission.
	 *
	 * @param mixed $post_id Post being commented on.
	 * @return void
	 */
	public static function mark_submission( $post_id = 0 ): void {
		self::$submission = max( 1, (int) $post_id );
	}

	/**
	 * Refuse the comment when the form checks fail.
	 *
	 * @param mixed $approved     Approval status so far (or a WP_Error).
	 * @param mixed $comment_data Comment data.
	 * @return mixed
	 */
	public static function filter_approved( $approved, $comment_data = [] ) {
		if ( 0 === self::$submission || $approved instanceof WP_Error ) {
			return $approved;
		}

		$post_id          = is_array( $comment_data ) ? (int) ( $comment_data['comment_post_ID'] ?? 0 ) : 0;
		self::$submission = 0;
		$ip               = IpDetector::get_ip();

		if ( self::is_exempt( $ip, $post_id ) ) {
			return $approved;
		}

		$verdict = CommentSpamCheck::evaluate( self::posted( CommentFields::HONEYPOT_FIELD ), self::posted( CommentFields::TOKEN_FIELD ), self::policy(), time() );

		if ( CommentSpamCheck::OK === $verdict ) {
			return $approved;
		}

		self::log( $verdict, $ip );

		if ( CommentSpamCheck::counts_toward_ban( $verdict ) ) {
			RegisterTracker::record_reject( 'comment_spam' );
		}

		return new WP_Error(
			'lw_fw_comment_spam',
			__( '<strong>Error:</strong> Your comment could not be submitted. Please reload the page and try again.', 'lw-firewall' ),
			403
		);
	}

	/**
	 * Whether this submitter bypasses the checks.
	 *
	 * @param string $ip      Resolved client IP.
	 * @param int    $post_id Post being commented on.
	 * @return bool
	 */
	private static function is_exempt( string $ip, int $post_id ): bool {
		$privileged = current_user_can( 'moderate_comments' )
			|| ( $post_id > 0 && current_user_can( 'edit_post', $post_id ) );

		return CommentSpamCheck::is_exempt(
			defined( 'WP_CLI' ) && WP_CLI,
			$privileged,
			$ip,
			(array) Options::get( 'ip_whitelist', [] )
		);
	}

	/**
	 * The active checks.
	 *
	 * @return array{honeypot: bool, token: bool, min_fill: int, max_age: int}
	 */
	private static function policy(): array {
		return [
			'honeypot' => ! empty( Options::get( 'comment_honeypot' ) ),
			'token'    => ! empty( Options::get( 'comment_token_enabled' ) ),
			'min_fill' => (int) Options::get( 'comment_min_fill_time', 2 ),
			'max_age'  => (int) Options::get( 'comment_token_max_age', DAY_IN_SECONDS ),
		];
	}

	/**
	 * A submitted form field, sanitized.
	 *
	 * @param string $field Field name.
	 * @return string
	 */
	private static function posted( string $field ): string {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Read-only spam check on the public comment POST; the form carries no nonce by design.
		if ( ! isset( $_POST[ $field ] ) || ! is_string( $_POST[ $field ] ) ) {
			return '';
		}

		return sanitize_text_field( wp_unslash( $_POST[ $field ] ) );
		// phpcs:enable WordPress.Security.NonceVerification.Missing
	}

	/**
	 * Log the refusal.
	 *
	 * @param string $verdict Verdict code.
	 * @param string $ip      Resolved client IP.
	 * @return void
	 */
	private static function log( string $verdict, string $ip ): void {
		if ( empty( Options::get( 'log_enabled' ) ) ) {
			return;
		}

		Logger::log(
			[
				'ip'     => $ip,
				'reason' => 'comment_spam (' . $verdict . ')',
				'ua'     => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 ),
				'url'    => sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ),
			]
		);
	}
}
