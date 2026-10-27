<?php
/**
 * Per-account cap on wrong second-factor answers.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Owned by the two-factor module, so the guessing budget does not depend on
 * the firewall's optional login lockouts (or on the MU-worker being healthy):
 * ten wrong answers for one account within 15 minutes block that account's
 * second-factor step for 15 minutes. Someone who knows the password can then
 * neither start a new pending login nor answer an existing one.
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
	 * Constructor.
	 *
	 * @param StorageInterface|null $storage Counters; null = the configured firewall storage.
	 */
	public function __construct( private readonly ?StorageInterface $storage = null ) {}

	/**
	 * Count a wrong answer.
	 *
	 * @param int $user_id User.
	 * @return bool Whether the account is now blocked.
	 */
	public function record_failure( int $user_id ): bool {
		$storage = $this->storage();
		if ( $storage->increment( 'twofa_fail_u' . $user_id, self::WINDOW ) < self::MAX_FAILURES ) {
			return false;
		}

		$storage->set( 'twofa_block_u' . $user_id, 1, self::BLOCK );
		$storage->delete( 'twofa_fail_u' . $user_id );

		return true;
	}

	/**
	 * Whether the account's second-factor step is blocked.
	 *
	 * @param int $user_id User.
	 */
	public function is_blocked( int $user_id ): bool {
		return ! empty( $this->storage()->get( 'twofa_block_u' . $user_id ) );
	}

	/**
	 * Counter storage.
	 */
	private function storage(): StorageInterface {
		return $this->storage ?? lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
	}
}
