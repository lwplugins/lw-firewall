<?php
/**
 * Pure verdict for a submitted comment or product review.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Decides whether a comment-form POST looks like a bot, and whether the
 * submitter is exempt from the check at all.
 *
 * No WordPress calls beyond the token's HMAC salt, so every rule is unit
 * testable; CommentGuard gathers the request facts and applies the verdict.
 */
final class CommentSpamCheck {

	/**
	 * Token scope: a registration or lost-password token is never accepted here.
	 */
	public const SCOPE = 'comment';

	public const OK        = '';
	public const HONEYPOT  = 'honeypot';
	public const NO_TOKEN  = 'no_token';
	public const BAD_TOKEN = 'bad_token';
	public const TOO_FAST  = 'too_fast';
	public const EXPIRED   = 'expired';

	/**
	 * Judge one submission.
	 *
	 * A missing honeypot field is not a failure: a theme with a hand-built
	 * comment form never renders it, and the honeypot must never reject a
	 * real visitor. Only a filled one is evidence.
	 *
	 * @param string                                                          $honeypot Submitted honeypot value.
	 * @param string                                                          $token    Submitted token.
	 * @param array{honeypot: bool, token: bool, min_fill: int, max_age: int} $policy   Active checks.
	 * @param int                                                             $now      Current UNIX time.
	 * @return string One of the class constants; OK when the submission passes.
	 */
	public static function evaluate( string $honeypot, string $token, array $policy, int $now ): string {
		if ( $policy['honeypot'] && '' !== trim( $honeypot ) ) {
			return self::HONEYPOT;
		}

		if ( ! $policy['token'] ) {
			return self::OK;
		}

		if ( '' === $token ) {
			return self::NO_TOKEN;
		}

		if ( RegisterToken::check( $token, $now, $policy['min_fill'], $policy['max_age'], null, self::SCOPE ) ) {
			return self::OK;
		}

		$issued = RegisterToken::issued_at( $token, self::SCOPE );

		if ( null === $issued ) {
			return self::BAD_TOKEN;
		}

		return ( $now - $issued ) > $policy['max_age'] ? self::EXPIRED : self::TOO_FAST;
	}

	/**
	 * Whether a refused submission is evidence enough to count toward a ban.
	 *
	 * An expired token was signed by this site for a page someone really
	 * loaded — most likely a visitor without JavaScript on a page the cache
	 * kept longer than the token lifetime. Refusing it is right; banning
	 * them for retrying is not.
	 *
	 * @param string $verdict Verdict from evaluate().
	 * @return bool
	 */
	public static function counts_toward_ban( string $verdict ): bool {
		return self::OK !== $verdict && self::EXPIRED !== $verdict;
	}

	/**
	 * Whether the submitter bypasses every check.
	 *
	 * @param bool               $cli        Running under WP-CLI.
	 * @param bool               $privileged Logged in with moderate_comments or edit rights on the post.
	 * @param string             $ip         Resolved client IP.
	 * @param array<int, string> $whitelist  IP whitelist entries.
	 * @return bool
	 */
	public static function is_exempt( bool $cli, bool $privileged, string $ip, array $whitelist ): bool {
		if ( $cli || $privileged ) {
			return true;
		}

		return ! empty( $whitelist ) && IpMatcher::matches( $ip, $whitelist );
	}
}
