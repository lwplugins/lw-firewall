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
 * ten wrong answers for one account within 15 minutes block that account's
 * second-factor step for 15 minutes. Someone who knows the password can then
 * neither start a new pending login nor answer an existing one.
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
	 * Count a wrong answer.
	 *
	 * @param int $user_id User.
	 * @return bool Whether the account is now blocked (also after a database error).
	 */
	public function record_failure( int $user_id ): bool {
		$counter = $this->counter();
		if ( $counter->increment( $user_id, self::META_KEY, self::WINDOW ) < self::MAX_FAILURES ) {
			return false;
		}

		// The block runs BLOCK seconds from the failure that reached the cap.
		$counter->hold( $user_id, self::META_KEY, self::MAX_FAILURES );

		return true;
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
	 * Counter.
	 */
	private function counter(): AttemptCounter {
		return $this->counter ?? new AttemptCounter();
	}
}
