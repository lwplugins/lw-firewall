<?php
/**
 * Tests for the client IP diagnostic (issue #6).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Status;

use LightweightPlugins\Firewall\Admin\Status\ClientIpDiagnostic;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Status\ClientIpDiagnostic
 */
final class ClientIpDiagnosticTest extends MonkeyTestCase {

	/**
	 * Server variables before the test.
	 *
	 * @var array<string, mixed>
	 */
	private array $server = array();

	protected function setUp(): void {
		parent::setUp();
		$this->server = $_SERVER;
	}

	protected function tearDown(): void {
		$_SERVER = $this->server;
		parent::tearDown();
	}

	/**
	 * @param array<string, mixed> $server   Request server variables.
	 * @param array<int, string>   $proxies  Trusted proxies.
	 * @return array<string, mixed>
	 */
	private static function diagnose( array $server, array $proxies = array() ): array {
		OptionStore::install( array( 'lw_firewall' => array( 'trusted_proxies' => $proxies ) ) );
		$_SERVER = $server;

		return ClientIpDiagnostic::build();
	}

	public function test_a_direct_visitor_resolves_to_remote_addr(): void {
		$result = self::diagnose( array( 'REMOTE_ADDR' => '8.8.8.8' ) );

		$this->assertSame( array( '8.8.8.8', 'remote_addr', true ), array( $result['detected_ip'], $result['source'], $result['routable'] ) );
	}

	public function test_a_trusted_proxy_hands_over_the_forwarded_address(): void {
		$result = self::diagnose(
			array(
				'REMOTE_ADDR'          => '127.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '8.8.4.4',
			),
			array( '127.0.0.1' )
		);

		$this->assertSame( array( '8.8.4.4', 'trusted_proxy', true ), array( $result['detected_ip'], $result['source'], $result['trusted_proxy_match'] ) );
	}

	public function test_an_untrusted_forwarded_header_is_listed_but_ignored(): void {
		$result = self::diagnose(
			array(
				'REMOTE_ADDR'          => '127.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '8.8.4.4',
			)
		);

		$this->assertSame(
			array( '127.0.0.1', false, false, array( array( 'name' => 'X-Forwarded-For', 'value' => '8.8.4.4' ) ) ),
			array( $result['detected_ip'], $result['routable'], $result['trusted_proxy_match'], $result['forwarded_headers'] )
		);
	}

	public function test_a_cloudflare_request_uses_the_connecting_ip(): void {
		$result = self::diagnose(
			array(
				'REMOTE_ADDR'           => '173.245.48.1',
				'HTTP_CF_CONNECTING_IP' => '8.8.8.8',
			)
		);

		$this->assertSame( array( '8.8.8.8', 'cloudflare', true ), array( $result['detected_ip'], $result['source'], $result['cloudflare'] ) );
	}

	public function test_header_values_are_stripped_of_control_characters_and_capped(): void {
		$headers = ClientIpDiagnostic::headers( array( 'HTTP_X_REAL_IP' => "1.2.3.4\r\nX-Evil: 1" . str_repeat( 'a', 400 ) ) );

		$this->assertSame( 300, strlen( $headers[0]['value'] ) );
		$this->assertStringNotContainsString( "\n", $headers[0]['value'] );
	}
}
