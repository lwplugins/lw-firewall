<?php
/**
 * End-to-end passkey tests: real ES256 keys, real library verification.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey;

use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\TwoFactor\UserMetaStubTrait;
use LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__, 2 ) . '/Support/WpError.php';
require_once dirname( __DIR__, 2 ) . '/Support/WpUser.php';

/**
 * No library double: the service builds the real lbuchs\WebAuthn\WebAuthn.
 *
 * @covers \LightweightPlugins\Firewall\TwoFactor\Passkey\PasskeyService
 * @covers \LightweightPlugins\Firewall\TwoFactor\Passkey\WebAuthnFactory
 */
final class PasskeyEndToEndTest extends MonkeyTestCase {

	use PasskeyStubTrait;
	use UserMetaStubTrait;

	private const ORIGIN = 'https://example.com';
	private const RP     = 'example.com';

	private PasskeyService $service;

	private SoftAuthenticator $device;

	private \WP_User $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->stub_passkey_wp( 'https://example.com/' );
		$this->stub_user_meta();
		$this->service = new PasskeyService();
		$this->device  = new SoftAuthenticator();
		$this->alice   = new \WP_User( 5, 'alice', 'Alice' );
	}

	/**
	 * Challenge bytes the browser would receive with these options.
	 *
	 * @param array<string, mixed> $options Options from the service.
	 */
	private static function challenge_of( array $options ): string {
		$bin = base64_decode( strtr( $options['publicKey']['challenge'], '-_', '+/' ), true );
		self::assertIsString( $bin );
		self::assertSame( 32, strlen( $bin ) );
		return $bin;
	}

	private function register(): PasskeyRecord {
		$out = $this->service->registration_options( $this->alice );
		$this->assertIsArray( $out );
		$this->assertSame( 'required', $out['options']['publicKey']['authenticatorSelection']['userVerification'] );
		$this->assertSame( 'required', $out['options']['publicKey']['authenticatorSelection']['residentKey'] );
		$this->assertSame( self::RP, $out['options']['publicKey']['rp']['id'] );

		$this->device->user_handle = (string) base64_decode( strtr( $out['options']['publicKey']['user']['id'], '-_', '+/' ), true );
		$resp                      = $this->device->create( self::challenge_of( $out['options'] ), self::ORIGIN, self::RP );

		$record = $this->service->finish_registration(
			$this->alice,
			$out['key'],
			SoftAuthenticator::b64url( $resp['client_data'] ),
			SoftAuthenticator::b64url( $resp['attestation'] ),
			'Phone'
		);
		$this->assertInstanceOf( PasskeyRecord::class, $record );

		return $record;
	}

	/**
	 * Run a passwordless assertion through the service.
	 *
	 * @param callable|null $tamper Mutates the posted credential.
	 * @return int|\WP_Error
	 */
	private function login( int $count, int $flags = SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV, string $origin = self::ORIGIN, string $rp = self::RP, ?callable $tamper = null, ?\WP_User $user = null ) {
		$out  = $this->service->assertion_options( $user );
		$cred = $this->device->get( self::challenge_of( $out['options'] ), $origin, $rp, $count, $flags );
		if ( null !== $tamper ) {
			$cred = $tamper( $cred );
		}
		return $this->service->verify_assertion( $out['key'], $cred );
	}

	public function test_real_registration_and_real_assertion(): void {
		$record = $this->register();

		$this->assertSame( SoftAuthenticator::b64url( $this->device->credential_id ), $record->credential_id );
		$this->assertSame(
			openssl_pkey_get_details( openssl_pkey_get_public( $record->public_key ) )['key'],
			$this->device->public_pem()
		);
		$this->assertSame( hash( 'sha256', $record->credential_id ), $record->id );

		$this->assertSame( 5, $this->login( 7 ) );
		$this->assertSame( 7, ( new UserFactors( 5 ) )->passkeys()[0]->sign_count );

		$this->assertSame( 5, $this->login( 8, SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV, self::ORIGIN, self::RP, null, $this->alice ) );
	}

	public function test_real_assertion_rejections(): void {
		$this->register();

		$flip_sig = static function ( array $c ): array {
			$sig                        = (string) base64_decode( strtr( $c['signature'], '-_', '+/' ), true );
			$sig[ strlen( $sig ) - 1 ]  = chr( ord( $sig[ strlen( $sig ) - 1 ] ) ^ 0x01 );
			$c['signature']             = SoftAuthenticator::b64url( $sig );
			return $c;
		};
		$this->assertSame( 'lwfw_passkey_invalid', $this->login( 1, SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV, self::ORIGIN, self::RP, $flip_sig )->get_error_code() );

		$this->assertSame( 'lwfw_passkey_invalid', $this->login( 1, SoftAuthenticator::FLAG_UP )->get_error_code(), 'UV is required' );
		$this->assertSame( 'lwfw_passkey_invalid', $this->login( 1, SoftAuthenticator::FLAG_UV )->get_error_code(), 'UP is required' );
		$this->assertSame( 'lwfw_passkey_invalid', $this->login( 1, SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV, 'https://evil.net' )->get_error_code() );
		$this->assertSame( 'lwfw_passkey_invalid', $this->login( 1, SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV, self::ORIGIN, 'evil.net' )->get_error_code() );

		$other = new SoftAuthenticator();
		$swap  = function ( array $c ) use ( $other ): array {
			$forged       = $other->get( random_bytes( 32 ), self::ORIGIN, self::RP, 1 );
			$c['signature'] = $forged['signature'];
			return $c;
		};
		$this->assertSame( 'lwfw_passkey_invalid', $this->login( 1, SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV, self::ORIGIN, self::RP, $swap )->get_error_code() );

		$this->assertSame( 0, ( new UserFactors( 5 ) )->passkeys()[0]->last_used_at );
		$this->assertSame( 5, $this->login( 2 ) );
		$this->assertSame( 'lwfw_passkey_clone', $this->login( 2 )->get_error_code() );
	}

	public function test_challenge_from_another_ceremony_is_rejected_by_library(): void {
		$this->register();
		$out  = $this->service->assertion_options( null );
		$cred = $this->device->get( random_bytes( 32 ), self::ORIGIN, self::RP, 1 );
		$this->assertSame( 'lwfw_passkey_invalid', $this->service->verify_assertion( $out['key'], $cred )->get_error_code() );
	}

	public function test_registration_without_uv_is_rejected(): void {
		$out  = $this->service->registration_options( $this->alice );
		$resp = $this->device->create( self::challenge_of( $out['options'] ), self::ORIGIN, self::RP, SoftAuthenticator::FLAG_UP );

		$result = $this->service->finish_registration( $this->alice, $out['key'], SoftAuthenticator::b64url( $resp['client_data'] ), SoftAuthenticator::b64url( $resp['attestation'] ), 'x' );
		$this->assertSame( 'lwfw_passkey_invalid', $result->get_error_code() );
		$this->assertSame( array(), ( new UserFactors( 5 ) )->passkeys() );
	}
}
