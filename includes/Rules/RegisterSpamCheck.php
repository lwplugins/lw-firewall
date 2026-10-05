<?php
/**
 * Pure verdict for a submitted registration form.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Decides whether a registration POST looks like a bot, and whether a refusal
 * is evidence enough to count toward the spam auto-ban.
 *
 * Single-use is not judged here: RegisterGuard spends the token only once the
 * submission is otherwise accepted, and reports a spent one as REPLAYED.
 */
final class RegisterSpamCheck {

	/**
	 * Token scope.
	 */
	public const SCOPE = 'reg';

	public const OK        = '';
	public const HONEYPOT  = 'honeypot';
	public const NO_TOKEN  = 'no_token';
	public const BAD_TOKEN = 'bad_token';
	public const TOO_FAST  = 'too_fast';
	public const EXPIRED   = 'expired';
	public const REPLAYED  = 'replayed';

	/**
	 * Judge one submission.
	 *
	 * @param string                                             $honeypot Submitted honeypot value.
	 * @param string                                             $token    Submitted token.
	 * @param array{honeypot: bool, min_fill: int, max_age: int} $policy Active checks.
	 * @param int                                                $now      Current UNIX time.
	 * @return string One of the class constants; OK when the submission passes.
	 */
	public static function evaluate( string $honeypot, string $token, array $policy, int $now ): string {
		if ( $policy['honeypot'] && '' !== trim( $honeypot ) ) {
			return self::HONEYPOT;
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
	 * Only what a person filling in a real form cannot produce counts: a
	 * filled honeypot, or a token that is missing or not signed by this site.
	 * An expired or already spent token comes from a page someone really
	 * loaded — a stale or shared page cache, a resent form — and a too-fast
	 * one can be browser autofill. Those are refused, never banned.
	 *
	 * @param string $verdict Verdict from evaluate(), or REPLAYED.
	 * @return bool
	 */
	public static function counts_toward_ban( string $verdict ): bool {
		return in_array( $verdict, [ self::HONEYPOT, self::NO_TOKEN, self::BAD_TOKEN ], true );
	}
}
