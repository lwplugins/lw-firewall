<?php
/**
 * A decoded, shape-checked assertion as posted by the browser.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Passkey;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Untrusted input → typed binary fields, or nothing.
 */
final class AssertionInput {

	/**
	 * Minimum authenticatorData length: rpIdHash (32) + flags (1) + signCount (4).
	 */
	private const AUTH_DATA_MIN = 37;

	/**
	 * Build from decoded fields.
	 *
	 * @param string $credential_id      Credential id, canonical base64url.
	 * @param string $client_data        clientDataJSON, raw.
	 * @param string $authenticator_data authenticatorData, raw.
	 * @param string $signature          Signature, raw.
	 * @param string $user_handle        User handle, raw ('' when absent).
	 */
	private function __construct(
		public readonly string $credential_id,
		public readonly string $client_data,
		public readonly string $authenticator_data,
		public readonly string $signature,
		public readonly string $user_handle
	) {}

	/**
	 * Parse a posted credential.
	 *
	 * @param array<string, mixed> $credential Fields in base64url.
	 * @return self|null Null when a field is missing or malformed.
	 */
	public static function parse( array $credential ): ?self {
		$fields = array();
		foreach ( array( 'id', 'clientDataJSON', 'authenticatorData', 'signature' ) as $name ) {
			$value = $credential[ $name ] ?? null;
			$bin   = is_string( $value ) ? Base64Url::decode( $value ) : null;
			if ( null === $bin || '' === $bin ) {
				return null;
			}
			$fields[ $name ] = $bin;
		}

		$handle = $credential['userHandle'] ?? null;
		if ( null === $handle ) {
			$handle = '';
		} elseif ( is_string( $handle ) ) {
			$handle = Base64Url::decode( $handle );
		}
		if ( ! is_string( $handle ) || strlen( $fields['authenticatorData'] ) < self::AUTH_DATA_MIN ) {
			return null;
		}

		return new self( Base64Url::encode( $fields['id'] ), $fields['clientDataJSON'], $fields['authenticatorData'], $fields['signature'], $handle );
	}

	/**
	 * Signature counter (32-bit big-endian at offset 33 of authenticatorData).
	 */
	public function sign_count(): int {
		$unpacked = unpack( 'N', substr( $this->authenticator_data, 33, 4 ) );

		return is_array( $unpacked ) ? (int) $unpacked[1] : 0;
	}
}
