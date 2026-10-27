<?php
/**
 * Per-account cap on wrong second-factor answers.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Owned by the two-factor module, so the guessing budget does not depend on
 * the firewall's optional login lockouts (or on the MU-worker being healthy):
 * ten answers for one account within 15 minutes without a success block that
 * account's second-factor step for 15 minutes. Someone who knows the password
 * can then neither start a new pending login nor answer an existing one.
 *
 * Every answer claims a slot (claim()) atomically BEFORE it is checked, so
 * parallel guesses over many pending tokens share the same ten slots; a
 * success gives the budget back (succeeded()).
 *
 * The count lives in the account's usermeta via AttemptCounter (atomic SQL,
 * fail closed: a database error reads as blocked), never in the request
 * storage, whose backends fail open.
 */
final class FailureThrottle {

	/**
	 * Wrong answers per window before the block.
	 */
	public const MAX_FAILURES = 10;

	/**
	 * Counting window in seconds.
	 */
	public const WINDOW = 900;

	/**
	 * Block length in seconds.
	 */
	public const BLOCK = 900;

	/**
	 * Usermeta key of the counter.
	 */
	public const META_KEY = '_lw_firewall_2fa_fail';

	/**
	 * Constructor.
	 *
	 * @param AttemptCounter|null $counter Counter; null = the database counter.
	 */
	public function __construct( private readonly ?AttemptCounter $counter = null ) {}

	/**
	 * Claim one answer slot before the answer is checked.
	 *
	 * @param int $user_id User.
	 * @return bool False when the budget is used up (the block then starts) or
	 *              on a database error: the answer must not be checked.
	 */
	public function claim( int $user_id ): bool {
		$count = $this->counter()->increment( $user_id, self::META_KEY, self::WINDOW );
		if ( $count <= self::MAX_FAILURES ) {
			return true;
		}

		$this->start_block( $user_id );

		return false;
	}

	/**
	 * A claimed answer was wrong: start the block once the budget is used up.
	 *
	 * @param int $user_id User.
	 * @return bool Whether the account is now blocked (also after a database error).
	 */
	public function record_failure( int $user_id ): bool {
		if ( $this->counter()->count( $user_id, self::META_KEY, self::WINDOW ) < self::MAX_FAILURES ) {
			return false;
		}

		$this->start_block( $user_id );

		return true;
	}

	/**
	 * A claimed answer was right: the account gets its full budget back.
	 *
	 * @param int $user_id User.
	 */
	public function succeeded( int $user_id ): void {
		$this->counter()->delete( $user_id, self::META_KEY );
	}

	/**
	 * Whether the account's second-factor step is blocked.
	 *
	 * @param int $user_id User.
	 */
	public function is_blocked( int $user_id ): bool {
		return $this->counter()->count( $user_id, self::META_KEY, self::BLOCK ) >= self::MAX_FAILURES;
	}

	/**
	 * The block runs BLOCK seconds from now. If that write fails, the counter
	 * keeps its value (at or over the cap), which is_blocked() still reads as
	 * blocked for the rest of the window, and a broken database reads as
	 * blocked anyway.
	 *
	 * @param int $user_id User.
	 */
	private function start_block( int $user_id ): void {
		$this->counter()->hold( $user_id, self::META_KEY, self::MAX_FAILURES );
	}

	/**
	 * Counter.
	 */
	private function counter(): AttemptCounter {
		return $this->counter ?? new AttemptCounter();
	}
}
