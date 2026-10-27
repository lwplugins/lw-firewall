<?php
/**
 * Per-user second-factor storage (TOTP, recovery codes, passkeys).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The only reader/writer of the two-factor user meta.
 */
final class UserFactors {

	public const META_TOTP     = '_lw_firewall_totp';
	public const META_RECOVERY = '_lw_firewall_recovery';
	public const META_PASSKEYS = '_lw_firewall_passkeys';
	public const META_LOOKUP   = '_lw_firewall_passkey_lookup';
	public const META_HANDLE   = '_lw_firewall_user_handle';
	public const META_SALT     = '_lw_firewall_remember_salt';
	public const META_SINCE    = '_lw_firewall_2fa_since';

	/**
	 * Passkey limit per user.
	 */
	private const MAX_PASSKEYS = 10;

	/**
	 * Bind the store to a user.
	 *
	 * @param int $user_id User ID.
	 */
	public function __construct( private readonly int $user_id ) {}

	/**
	 * Whether a readable TOTP secret is stored.
	 */
	public function has_totp(): bool {
		return null !== $this->totp_secret();
	}

	/**
	 * Base32 TOTP secret, or null when absent or no longer decryptable.
	 */
	public function totp_secret(): ?string {
		$data = $this->totp_data();
		if ( ! isset( $data['secret'] ) || ! is_string( $data['secret'] ) ) {
			return null;
		}

		return SecretBox::open( $data['secret'] );
	}

	/**
	 * Last accepted TOTP time step (replay guard).
	 */
	public function totp_last_step(): int {
		return (int) ( $this->totp_data()['last_step'] ?? 0 );
	}

	/**
	 * Store a new TOTP secret (sealed), resetting the replay counter.
	 *
	 * @param string $secret_b32 Base32 secret.
	 */
	public function save_totp( string $secret_b32 ): void {
		update_user_meta(
			$this->user_id,
			self::META_TOTP,
			array(
				'secret'       => SecretBox::seal( $secret_b32 ),
				'last_step'    => 0,
				'confirmed_at' => time(),
			)
		);
	}

	/**
	 * Remember the last accepted time step.
	 *
	 * @param int $step Time step.
	 */
	public function mark_totp_step( int $step ): void {
		$data = $this->totp_data();
		if ( ! $data ) {
			return;
		}
		$data['last_step'] = $step;
		update_user_meta( $this->user_id, self::META_TOTP, $data );
	}

	/**
	 * Remove the TOTP factor.
	 */
	public function delete_totp(): void {
		delete_user_meta( $this->user_id, self::META_TOTP );
	}

	/**
	 * Stored recovery code hashes.
	 *
	 * @return string[]
	 */
	public function recovery_hashes(): array {
		$hashes = get_user_meta( $this->user_id, self::META_RECOVERY, true );

		return is_array( $hashes ) ? array_values( array_map( 'strval', $hashes ) ) : array();
	}

	/**
	 * Replace the recovery code hashes.
	 *
	 * @param string[] $hashes Hashes.
	 */
	public function set_recovery( array $hashes ): void {
		update_user_meta( $this->user_id, self::META_RECOVERY, array_values( $hashes ) );
	}

	/**
	 * Registered passkeys.
	 *
	 * @return PasskeyRecord[]
	 */
	public function passkeys(): array {
		$rows = get_user_meta( $this->user_id, self::META_PASSKEYS, true );
		if ( ! is_array( $rows ) ) {
			return array();
		}

		$out = array();
		foreach ( $rows as $row ) {
			$record = is_array( $row ) ? PasskeyRecord::from_array( $row ) : null;
			if ( null !== $record ) {
				$out[] = $record;
			}
		}

		return $out;
	}

	/**
	 * Add a passkey.
	 *
	 * @param PasskeyRecord $record Record.
	 * @return bool False over the 10 key limit or for a duplicate credential.
	 */
	public function add_passkey( PasskeyRecord $record ): bool {
		$keys = $this->passkeys();
		if ( count( $keys ) >= self::MAX_PASSKEYS ) {
			return false;
		}
		foreach ( $keys as $key ) {
			if ( $key->credential_id === $record->credential_id ) {
				return false;
			}
		}

		$keys[] = $record;
		$this->save_passkeys( $keys );
		add_user_meta( $this->user_id, self::META_LOOKUP, hash( 'sha256', $record->credential_id ), false );

		return true;
	}

	/**
	 * Record a successful passkey use.
	 *
	 * @param string $id         Passkey id (hex sha256).
	 * @param int    $sign_count New signature counter.
	 */
	public function update_passkey_usage( string $id, int $sign_count ): void {
		$keys = $this->passkeys();
		foreach ( $keys as $i => $key ) {
			if ( $key->id === $id ) {
				$keys[ $i ] = $key->with_usage( $sign_count, time() );
				$this->save_passkeys( $keys );
				return;
			}
		}
	}

	/**
	 * Remove a passkey and its lookup row.
	 *
	 * @param string $id Passkey id (hex sha256).
	 * @return bool Whether it existed.
	 */
	public function remove_passkey( string $id ): bool {
		$keys   = $this->passkeys();
		$kept   = array();
		$lookup = null;
		foreach ( $keys as $key ) {
			if ( $key->id === $id ) {
				$lookup = hash( 'sha256', $key->credential_id );
			} else {
				$kept[] = $key;
			}
		}
		if ( null === $lookup ) {
			return false;
		}

		$this->save_passkeys( $kept );
		delete_user_meta( $this->user_id, self::META_LOOKUP, $lookup );

		return true;
	}

	/**
	 * WebAuthn user handle (16 random bytes hex), created on first use.
	 */
	public function user_handle(): string {
		return $this->lazy_hex( self::META_HANDLE );
	}

	/**
	 * Per-user salt for "remember this device" tokens, created on first use.
	 */
	public function remember_salt(): string {
		return $this->lazy_hex( self::META_SALT );
	}

	/**
	 * Whether the user has any second factor.
	 */
	public function has_any(): bool {
		return $this->has_totp() || array() !== $this->passkeys();
	}

	/**
	 * Delete every factor and rotate the remember salt (invalidates remembered devices).
	 */
	public function reset_all(): void {
		foreach ( array( self::META_TOTP, self::META_RECOVERY, self::META_PASSKEYS, self::META_LOOKUP, self::META_HANDLE, self::META_SALT ) as $meta ) {
			delete_user_meta( $this->user_id, $meta );
		}
		update_user_meta( $this->user_id, self::META_SALT, bin2hex( random_bytes( 16 ) ) );
	}

	/**
	 * Find the user owning a credential.
	 *
	 * @param string $credential_id_b64url Credential id as given (base64url).
	 * @return int|null User ID.
	 */
	public static function find_user_by_credential( string $credential_id_b64url ): ?int {
		$ids = get_users(
			array(
				'meta_key'   => self::META_LOOKUP, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Single indexed lookup by credential hash.
				'meta_value' => hash( 'sha256', $credential_id_b64url ), // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'number'     => 1,
				'fields'     => 'ID',
				'blog_id'    => 0,
			)
		);

		return array() === $ids ? null : (int) $ids[0];
	}

	/**
	 * Stored TOTP array.
	 *
	 * @return array<string, mixed>
	 */
	private function totp_data(): array {
		$data = get_user_meta( $this->user_id, self::META_TOTP, true );

		return is_array( $data ) ? $data : array();
	}

	/**
	 * Persist the passkey list.
	 *
	 * @param PasskeyRecord[] $keys Records.
	 */
	private function save_passkeys( array $keys ): void {
		update_user_meta(
			$this->user_id,
			self::META_PASSKEYS,
			array_map( static fn ( PasskeyRecord $key ): array => $key->to_array(), $keys )
		);
	}

	/**
	 * Read or lazily create a 32 char hex meta value.
	 *
	 * @param string $meta Meta key.
	 */
	private function lazy_hex( string $meta ): string {
		$value = get_user_meta( $this->user_id, $meta, true );
		if ( is_string( $value ) && 1 === preg_match( '/^[0-9a-f]{32}$/', $value ) ) {
			return $value;
		}

		$value = bin2hex( random_bytes( 16 ) );
		update_user_meta( $this->user_id, $meta, $value );

		return $value;
	}
}
