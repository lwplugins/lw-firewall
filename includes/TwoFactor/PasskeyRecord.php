<?php
/**
 * One registered passkey (immutable value object).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stored shape of a passkey credential.
 */
final class PasskeyRecord {

	/**
	 * Label length cap.
	 */
	private const LABEL_MAX = 60;

	/**
	 * Hex sha256 of the credential id.
	 *
	 * @var string
	 */
	public readonly string $id;

	/**
	 * Trimmed, tag-free label (max 60 chars).
	 *
	 * @var string
	 */
	public readonly string $label;

	/**
	 * Build a record.
	 *
	 * @param string $id            Hex sha256 of the credential id.
	 * @param string $credential_id Credential id, base64url.
	 * @param string $public_key    Public key, PEM.
	 * @param int    $sign_count    Last seen signature counter.
	 * @param string $label         User-given name.
	 * @param int    $created_at    Unix time.
	 * @param int    $last_used_at  Unix time, 0 = never.
	 */
	public function __construct(
		string $id,
		public readonly string $credential_id,
		public readonly string $public_key,
		public readonly int $sign_count,
		string $label,
		public readonly int $created_at,
		public readonly int $last_used_at
	) {
		$this->id    = $id;
		$this->label = mb_substr( trim( wp_strip_all_tags( $label ) ), 0, self::LABEL_MAX );
	}

	/**
	 * Copy with a new counter and usage time.
	 *
	 * @param int $sign_count   New counter.
	 * @param int $last_used_at New usage time.
	 */
	public function with_usage( int $sign_count, int $last_used_at ): self {
		return new self( $this->id, $this->credential_id, $this->public_key, $sign_count, $this->label, $this->created_at, $last_used_at );
	}

	/**
	 * Storage array.
	 *
	 * @return array<string, int|string>
	 */
	public function to_array(): array {
		return array(
			'id'            => $this->id,
			'credential_id' => $this->credential_id,
			'public_key'    => $this->public_key,
			'sign_count'    => $this->sign_count,
			'label'         => $this->label,
			'created_at'    => $this->created_at,
			'last_used_at'  => $this->last_used_at,
		);
	}

	/**
	 * Rebuild from a storage array.
	 *
	 * @param array<mixed> $data Stored data.
	 * @return self|null Null when a field is missing or mistyped.
	 */
	public static function from_array( array $data ): ?self {
		foreach ( array( 'id', 'credential_id', 'public_key', 'label' ) as $key ) {
			if ( ! isset( $data[ $key ] ) || ! is_string( $data[ $key ] ) ) {
				return null;
			}
		}
		foreach ( array( 'sign_count', 'created_at', 'last_used_at' ) as $key ) {
			if ( ! isset( $data[ $key ] ) || ! is_numeric( $data[ $key ] ) ) {
				return null;
			}
		}

		return new self(
			$data['id'],
			$data['credential_id'],
			$data['public_key'],
			(int) $data['sign_count'],
			$data['label'],
			(int) $data['created_at'],
			(int) $data['last_used_at']
		);
	}
}
