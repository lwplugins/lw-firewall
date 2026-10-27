<?php
/**
 * A software WebAuthn authenticator (ES256, "none" attestation) for end-to-end tests.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey;

/**
 * Produces real attestation objects and signed assertions, byte for byte as a
 * browser + platform authenticator would, so the real library can verify them.
 */
final class SoftAuthenticator {

	public const FLAG_UP = 0x01;
	public const FLAG_UV = 0x04;
	public const FLAG_AT = 0x40;

	/**
	 * P-256 key pair.
	 *
	 * @var \OpenSSLAsymmetricKey
	 */
	private \OpenSSLAsymmetricKey $key;

	/**
	 * Raw credential id.
	 */
	public readonly string $credential_id;

	/**
	 * User handle (binary) the authenticator stored at registration.
	 */
	public string $user_handle = '';

	public function __construct() {
		$key = openssl_pkey_new(
			array(
				'curve_name'       => 'prime256v1',
				'private_key_type' => OPENSSL_KEYTYPE_EC,
			)
		);
		if ( false === $key ) {
			throw new \RuntimeException( 'openssl_pkey_new failed' );
		}
		$this->key           = $key;
		$this->credential_id = random_bytes( 32 );
	}

	public static function b64url( string $bin ): string {
		return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' );
	}

	public function public_pem(): string {
		return openssl_pkey_get_details( $this->key )['key'];
	}

	/**
	 * Registration response (clientDataJSON + attestationObject), binary.
	 *
	 * @return array{client_data: string, attestation: string}
	 */
	public function create( string $challenge_bin, string $origin, string $rp_id, int $flags = self::FLAG_UP | self::FLAG_UV, int $count = 0 ): array {
		$client_data = $this->client_data( 'webauthn.create', $challenge_bin, $origin );
		$auth_data   = hash( 'sha256', $rp_id, true ) . chr( $flags | self::FLAG_AT ) . pack( 'N', $count )
			. str_repeat( "\0", 16 ) . pack( 'n', strlen( $this->credential_id ) ) . $this->credential_id . $this->cose_key();

		$attestation = self::map(
			array(
				array( self::text( 'fmt' ), self::text( 'none' ) ),
				array( self::text( 'attStmt' ), self::map( array() ) ),
				array( self::text( 'authData' ), self::bytes( $auth_data ) ),
			)
		);

		return array(
			'client_data' => $client_data,
			'attestation' => $attestation,
		);
	}

	/**
	 * Assertion as the browser posts it (all fields base64url).
	 *
	 * @return array<string, string>
	 */
	public function get( string $challenge_bin, string $origin, string $rp_id, int $count, int $flags = self::FLAG_UP | self::FLAG_UV, string $type = 'webauthn.get' ): array {
		$client_data = $this->client_data( $type, $challenge_bin, $origin );
		$auth_data   = hash( 'sha256', $rp_id, true ) . chr( $flags ) . pack( 'N', $count );
		$signature   = '';
		if ( ! openssl_sign( $auth_data . hash( 'sha256', $client_data, true ), $signature, $this->key, OPENSSL_ALGO_SHA256 ) ) {
			throw new \RuntimeException( 'openssl_sign failed' );
		}

		return array(
			'id'                => self::b64url( $this->credential_id ),
			'clientDataJSON'    => self::b64url( $client_data ),
			'authenticatorData' => self::b64url( $auth_data ),
			'signature'         => self::b64url( $signature ),
			'userHandle'        => self::b64url( $this->user_handle ),
		);
	}

	private function client_data( string $type, string $challenge_bin, string $origin ): string {
		return (string) json_encode(
			array(
				'type'        => $type,
				'challenge'   => self::b64url( $challenge_bin ),
				'origin'      => $origin,
				'crossOrigin' => false,
			),
			JSON_UNESCAPED_SLASHES
		);
	}

	/**
	 * COSE_Key (EC2, ES256, P-256).
	 */
	private function cose_key(): string {
		$ec = openssl_pkey_get_details( $this->key )['ec'];

		return self::map(
			array(
				array( self::int( 1 ), self::int( 2 ) ),
				array( self::int( 3 ), self::int( -7 ) ),
				array( self::int( -1 ), self::int( 1 ) ),
				array( self::int( -2 ), self::bytes( str_pad( $ec['x'], 32, "\0", STR_PAD_LEFT ) ) ),
				array( self::int( -3 ), self::bytes( str_pad( $ec['y'], 32, "\0", STR_PAD_LEFT ) ) ),
			)
		);
	}

	private static function head( int $major, int $len ): string {
		if ( $len < 24 ) {
			return chr( ( $major << 5 ) | $len );
		}
		if ( $len < 256 ) {
			return chr( ( $major << 5 ) | 24 ) . chr( $len );
		}
		return chr( ( $major << 5 ) | 25 ) . pack( 'n', $len );
	}

	private static function int( int $n ): string {
		return $n >= 0 ? self::head( 0, $n ) : self::head( 1, -1 - $n );
	}

	private static function bytes( string $b ): string {
		return self::head( 2, strlen( $b ) ) . $b;
	}

	private static function text( string $t ): string {
		return self::head( 3, strlen( $t ) ) . $t;
	}

	/**
	 * CBOR map from encoded key/value pairs.
	 *
	 * @param array<int, array{0: string, 1: string}> $pairs Pairs.
	 */
	private static function map( array $pairs ): string {
		$out = self::head( 5, count( $pairs ) );
		foreach ( $pairs as $pair ) {
			$out .= $pair[0] . $pair[1];
		}
		return $out;
	}
}
