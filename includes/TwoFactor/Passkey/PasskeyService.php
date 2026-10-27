<?php
/**
 * Passkey registration and assertion ceremonies.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor\Passkey;

use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;
use WP_Error;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The only code that talks to the WebAuthn library. User verification and user
 * presence are required in both ceremonies; every library exception becomes a
 * WP_Error with a PasskeyError code. Challenges are consumed before any check.
 */
final class PasskeyService {

	private const PURPOSE_REGISTER = 'register';
	private const PURPOSE_2FA      = 'assert_2fa';
	private const PURPOSE_LOGIN    = 'assert_login';

	/**
	 * Ceremony timeout in seconds (same as the challenge lifetime).
	 */
	private const TIMEOUT = ChallengeStore::TTL;

	/**
	 * Inject a library instance (tests); null = a fresh one per ceremony.
	 *
	 * @param object|null $webauthn Library instance.
	 */
	public function __construct( private readonly ?object $webauthn = null ) {}

	/**
	 * Options for navigator.credentials.create() (as { publicKey: … }).
	 *
	 * @param WP_User $user Registering user.
	 * @return array{key: string, options: array<string, mixed>}|WP_Error
	 */
	public function registration_options( WP_User $user ): array|WP_Error {
		try {
			return WebAuthnFactory::isolated(
				function () use ( $user ): array {
					$factors = new UserFactors( (int) $user->ID );
					$lib     = $this->library();
					$args    = $lib->getCreateArgs(
						(string) hex2bin( $factors->user_handle() ),
						(string) $user->user_login,
						'' !== (string) $user->display_name ? (string) $user->display_name : (string) $user->user_login,
						self::TIMEOUT,
						true,
						true,
						null,
						$this->credential_ids( $factors )
					);

					return $this->issue( $lib, $args, self::PURPOSE_REGISTER, (int) $user->ID );
				}
			);
		} catch ( \Throwable $e ) {
			return PasskeyError::make( PasskeyError::INVALID, $e );
		}
	}

	/**
	 * Verify a registration response and store the new passkey.
	 *
	 * @param WP_User $user            Registering user (must own the challenge).
	 * @param string  $key             Challenge key from registration_options().
	 * @param string  $client_data_b64 clientDataJSON, base64url.
	 * @param string  $attestation_b64 attestationObject, base64url.
	 * @param string  $label           User-given name.
	 */
	public function finish_registration( WP_User $user, string $key, string $client_data_b64, string $attestation_b64, string $label ): PasskeyRecord|WP_Error {
		$challenge = ChallengeStore::take( $key, self::PURPOSE_REGISTER );
		if ( null === $challenge || $user->ID <= 0 || $challenge['user_id'] !== (int) $user->ID ) {
			return PasskeyError::make( PasskeyError::CHALLENGE );
		}

		$client_data = Base64Url::decode( $client_data_b64 );
		$attestation = Base64Url::decode( $attestation_b64 );
		if ( null === $client_data || null === $attestation || ! $this->origin_ok( $client_data ) ) {
			return PasskeyError::make( PasskeyError::INVALID );
		}

		try {
			$created = WebAuthnFactory::isolated(
				fn (): array => get_object_vars( $this->library()->processCreate( $client_data, $attestation, $challenge['challenge'], true, true, true, true ) )
			);
		} catch ( \Throwable $e ) {
			return PasskeyError::make( PasskeyError::INVALID, $e );
		}

		$cred_bin = is_string( $created['credentialId'] ?? null ) ? $created['credentialId'] : '';
		$pem      = is_string( $created['credentialPublicKey'] ?? null ) ? $created['credentialPublicKey'] : '';
		if ( '' === $cred_bin || '' === $pem ) {
			return PasskeyError::make( PasskeyError::INVALID );
		}

		return $this->store( (int) $user->ID, Base64Url::encode( $cred_bin ), $pem, (int) ( $created['signatureCounter'] ?? 0 ), $label );
	}

	/**
	 * Options for navigator.credentials.get() (as { publicKey: … }).
	 *
	 * @param WP_User|null $user Second-factor user, or null for a discoverable
	 *                           (passwordless) request with no allowCredentials.
	 * @return array{key: string, options: array<string, mixed>}|WP_Error
	 */
	public function assertion_options( ?WP_User $user ): array|WP_Error {
		$user_id = null === $user ? 0 : (int) $user->ID;
		$purpose = null === $user ? self::PURPOSE_LOGIN : self::PURPOSE_2FA;
		try {
			return WebAuthnFactory::isolated(
				function () use ( $user_id, $purpose ): array {
					$ids  = $user_id > 0 ? $this->credential_ids( new UserFactors( $user_id ) ) : array();
					$lib  = $this->library();
					$args = $lib->getGetArgs( $ids, self::TIMEOUT, true, true, true, true, true, true );

					return $this->issue( $lib, $args, $purpose, $user_id );
				}
			);
		} catch ( \Throwable $e ) {
			return PasskeyError::make( PasskeyError::INVALID, $e );
		}
	}

	/**
	 * Verify an assertion.
	 *
	 * Second factor: pass the pending user's ID. The challenge must be a 2FA
	 * challenge issued for exactly that user, and the credential must be one
	 * of that user's passkeys. Passwordless: pass null. The challenge must be a
	 * discoverable one, and the userHandle is mandatory.
	 *
	 * @param string               $key              Challenge key from assertion_options().
	 * @param array<string, mixed> $credential       id, clientDataJSON, authenticatorData,
	 *                                               signature, userHandle (base64url).
	 * @param int|null             $expected_user_id Pending 2FA user, null = passwordless.
	 * @return int|WP_Error User ID.
	 */
	public function verify_assertion( string $key, array $credential, ?int $expected_user_id = null ): int|WP_Error {
		$challenge = ChallengeStore::take( $key, null === $expected_user_id ? self::PURPOSE_LOGIN : self::PURPOSE_2FA );
		if ( null === $challenge || ( null === $expected_user_id && 0 !== $challenge['user_id'] ) ) {
			return PasskeyError::make( PasskeyError::CHALLENGE );
		}
		if ( null !== $expected_user_id && ( $expected_user_id <= 0 || $challenge['user_id'] !== $expected_user_id ) ) {
			return PasskeyError::make( PasskeyError::UNKNOWN );
		}

		$input = AssertionInput::parse( $credential );
		if ( null === $input ) {
			return PasskeyError::make( PasskeyError::INVALID );
		}

		$user_id = UserFactors::find_user_by_credential( $input->credential_id );
		$factors = null === $user_id ? null : new UserFactors( $user_id );
		$record  = null === $factors ? null : $this->find_record( $factors, $input->credential_id );
		if ( null === $user_id || null === $record || ( null !== $expected_user_id && $expected_user_id !== $user_id ) ) {
			return PasskeyError::make( PasskeyError::UNKNOWN );
		}

		$handle_required = null === $expected_user_id;
		if ( ( $handle_required || '' !== $input->user_handle ) && ! hash_equals( $factors->user_handle(), bin2hex( $input->user_handle ) ) ) {
			return PasskeyError::make( PasskeyError::HANDLE );
		}

		return $this->check_signature( $user_id, $record, $input, $challenge['challenge'] );
	}

	/**
	 * Library signature check, then the clone guard and the usage update.
	 *
	 * @param int            $user_id   Owner.
	 * @param PasskeyRecord  $record    Stored passkey.
	 * @param AssertionInput $input     Decoded assertion.
	 * @param string         $challenge Challenge bytes.
	 * @return int|WP_Error
	 */
	private function check_signature( int $user_id, PasskeyRecord $record, AssertionInput $input, string $challenge ): int|WP_Error {
		if ( ! $this->origin_ok( $input->client_data ) ) {
			return PasskeyError::make( PasskeyError::INVALID );
		}

		try {
			$ok = WebAuthnFactory::isolated(
				fn () => $this->library()->processGet( $input->client_data, $input->authenticator_data, $input->signature, $record->public_key, $challenge, null, true, true )
			);
		} catch ( \Throwable $e ) {
			return PasskeyError::make( PasskeyError::INVALID, $e );
		}
		if ( true !== $ok ) {
			return PasskeyError::make( PasskeyError::INVALID );
		}

		$count = $input->sign_count();
		if ( $record->sign_count > 0 && $count <= $record->sign_count ) {
			return PasskeyError::make( PasskeyError::CLONED );
		}

		( new UserFactors( $user_id ) )->update_passkey_usage( $record->id, $count );

		return $user_id;
	}

	/**
	 * Persist a verified credential.
	 *
	 * @param int    $user_id    Owner.
	 * @param string $credential Credential id, base64url.
	 * @param string $pem        Public key.
	 * @param int    $count      Initial signature counter.
	 * @param string $label      Raw label.
	 */
	private function store( int $user_id, string $credential, string $pem, int $count, string $label ): PasskeyRecord|WP_Error {
		if ( '' === trim( wp_strip_all_tags( $label ) ) ) {
			$label = __( 'Passkey', 'lw-firewall' );
		}
		$record = new PasskeyRecord( hash( 'sha256', $credential ), $credential, $pem, max( 0, $count ), $label, time(), 0 );

		// A credential id is globally unique: refuse one already owned by anyone.
		if ( null !== UserFactors::find_user_by_credential( $credential ) || ! ( new UserFactors( $user_id ) )->add_passkey( $record ) ) {
			return PasskeyError::make( PasskeyError::LIMIT );
		}

		return $record;
	}

	/**
	 * Store the ceremony challenge and return the browser payload.
	 *
	 * @param object $lib     Library (the one that built $args; lbuchs\WebAuthn API).
	 * @param object $args    Library options object.
	 * @param string $purpose Ceremony.
	 * @param int    $user_id Bound user.
	 * @return array{key: string, options: array<string, mixed>}
	 * @throws \RuntimeException On an unusable challenge or encoding failure.
	 */
	private function issue( object $lib, object $args, string $purpose, int $user_id ): array {
		$raw       = $lib->getChallenge();
		$challenge = is_object( $raw ) && method_exists( $raw, 'getBinaryString' ) ? (string) $raw->getBinaryString() : '';
		$json      = wp_json_encode( $args );
		$options   = is_string( $json ) ? json_decode( $json, true ) : null;
		if ( strlen( $challenge ) < 16 || ! is_array( $options ) ) {
			throw new \RuntimeException( 'Unusable WebAuthn challenge or options.' );
		}

		return array(
			'key'     => ChallengeStore::put( $purpose, $challenge, $user_id ),
			'options' => $options,
		);
	}

	/**
	 * Raw credential ids of a user's passkeys.
	 *
	 * @param UserFactors $factors Store.
	 * @return string[]
	 */
	private function credential_ids( UserFactors $factors ): array {
		$ids = array();
		foreach ( $factors->passkeys() as $passkey ) {
			$bin = Base64Url::decode( $passkey->credential_id );
			if ( null !== $bin && '' !== $bin ) {
				$ids[] = $bin;
			}
		}

		return $ids;
	}

	/**
	 * The user's passkey with this credential id.
	 *
	 * @param UserFactors $factors    Store.
	 * @param string      $credential Credential id, base64url.
	 */
	private function find_record( UserFactors $factors, string $credential ): ?PasskeyRecord {
		foreach ( $factors->passkeys() as $passkey ) {
			if ( hash_equals( $passkey->credential_id, $credential ) ) {
				return $passkey;
			}
		}

		return null;
	}

	/**
	 * Whether clientDataJSON names an allowed origin and is not cross-origin.
	 *
	 * @param string $client_data Raw clientDataJSON.
	 */
	private function origin_ok( string $client_data ): bool {
		$data = json_decode( $client_data, true );

		return is_array( $data )
			&& false === ( $data['crossOrigin'] ?? false )
			&& isset( $data['origin'] ) && is_string( $data['origin'] )
			&& OriginPolicy::allowed( $data['origin'] );
	}

	/**
	 * Library for one ceremony.
	 *
	 * @return \lbuchs\WebAuthn\WebAuthn
	 */
	private function library(): object {
		return $this->webauthn ?? WebAuthnFactory::create();
	}
}
