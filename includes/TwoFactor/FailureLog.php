<?php
/**
 * Request-log entries of the two-factor module.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Writes a refused second-factor step to the firewall request log (when the
 * log is on). The URL is logged without its query string, which can carry
 * the pending token.
 */
final class FailureLog {

	/**
	 * Wrong code, recovery code, or a throttled account.
	 */
	public const TWOFA_FAILED = 'twofa_failed';

	/**
	 * Passkey not accepted as the second factor.
	 */
	public const PASSKEY_FAILED = 'twofa_passkey_failed';

	/**
	 * Log one refusal.
	 *
	 * @param string $reason One of the constants.
	 */
	public static function record( string $reason ): void {
		Logger::log(
			array(
				'ip'     => IpDetector::get_ip(),
				'reason' => $reason,
				'ua'     => LoginRequest::user_agent(),
				'url'    => LoginRequest::uri(),
			)
		);
	}

	/**
	 * Reason of a wrong answer by method.
	 *
	 * @param string $method Method tried.
	 */
	public static function reason_for( string $method ): string {
		return SecondFactorVerifier::PASSKEY === $method ? self::PASSKEY_FAILED : self::TWOFA_FAILED;
	}
}
