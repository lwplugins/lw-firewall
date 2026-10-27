<?php
/**
 * Test double for the WebAuthn library.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor\Passkey;

use lbuchs\WebAuthn\Binary\ByteBuffer;
use lbuchs\WebAuthn\WebAuthnException;

/**
 * Records every call; the process* methods succeed unless $fail is set.
 */
final class FakeWebAuthn {

	/**
	 * Arguments per method name.
	 *
	 * @var array<string, array<int, mixed>>
	 */
	public array $calls = array();

	public bool $fail = false;

	public string $challenge;

	public ?\stdClass $create_result = null;

	public function __construct() {
		$this->challenge = random_bytes( 32 );
	}

	public function getChallenge(): ByteBuffer {
		return new ByteBuffer( $this->challenge );
	}

	public function getCreateArgs( ...$args ): \stdClass {
		$this->calls['getCreateArgs'] = $args;
		return (object) array( 'publicKey' => (object) array( 'rp' => (object) array( 'id' => 'example.com' ) ) );
	}

	public function getGetArgs( ...$args ): \stdClass {
		$this->calls['getGetArgs'] = $args;
		return (object) array( 'publicKey' => (object) array( 'rpId' => 'example.com' ) );
	}

	public function processCreate( ...$args ): \stdClass {
		$this->calls['processCreate'] = $args;
		if ( $this->fail ) {
			throw new WebAuthnException( 'SECRET-LIBRARY-DETAIL', WebAuthnException::INVALID_SIGNATURE );
		}
		return $this->create_result ?? (object) array(
			'credentialId'        => 'raw-credential-id',
			'credentialPublicKey' => "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
			'signatureCounter'    => null,
		);
	}

	public function processGet( ...$args ): bool {
		$this->calls['processGet'] = $args;
		if ( $this->fail ) {
			throw new WebAuthnException( 'SECRET-LIBRARY-DETAIL', WebAuthnException::INVALID_SIGNATURE );
		}
		return true;
	}
}
