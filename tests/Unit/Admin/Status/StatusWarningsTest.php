<?php
/**
 * Tests for the status warnings.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Status;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Admin\Status\StatusWarnings;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Status\StatusWarnings
 */
final class StatusWarningsTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubTranslationFunctions();
	}

	/**
	 * A healthy status, with one block overridden.
	 *
	 * @param string               $block     Block to override.
	 * @param array<string, mixed> $overrides Keys to set in it.
	 * @return array<string, mixed>
	 */
	private static function healthy( string $block = '', array $overrides = array() ): array {
		$status = array(
			'firewall'  => array( 'enabled' => true ),
			'worker'    => array(
				'installed'       => true,
				'outdated'        => false,
				'kill_switch'     => false,
				'last_seen'       => 100,
				'last_attempt'    => null,
				'mu_dir_writable' => true,
			),
			'storage'   => array(
				'backend'           => 'apcu',
				'probe'             => array( 'ok' => true, 'message' => '' ),
				'file_dir_writable' => true,
			),
			'client_ip' => array(
				'detected_ip'         => '8.8.8.8',
				'remote_addr'         => '8.8.8.8',
				'routable'            => true,
				'cloudflare'          => false,
				'trusted_proxy_match' => false,
				'forwarded_headers'   => array(),
			),
			'geo'       => array(
				'active'    => true,
				'countries' => array( array( 'cc' => 'CN', 'stale' => false ) ),
			),
			'alerts'    => array(
				'pending'    => 0,
				'mail_error' => false,
			),
		);

		if ( '' !== $block ) {
			$status[ $block ] = array_merge( $status[ $block ], $overrides );
		}

		return $status;
	}

	/**
	 * @param array<string, mixed> $status Status.
	 * @return array<int, string>
	 */
	private static function codes( array $status ): array {
		return array_column( StatusWarnings::from( $status ), 'code' );
	}

	public function test_a_healthy_site_has_no_warnings(): void {
		$this->assertSame( array(), self::codes( self::healthy() ) );
	}

	/**
	 * @dataProvider provide_problems
	 *
	 * @param string               $block     Block.
	 * @param array<string, mixed> $overrides Problem.
	 * @param string               $code      Expected warning code.
	 */
	public function test_flags_each_problem( string $block, array $overrides, string $code ): void {
		$this->assertContains( $code, self::codes( self::healthy( $block, $overrides ) ) );
	}

	/**
	 * @return array<string, array{0: string, 1: array<string, mixed>, 2: string}>
	 */
	public static function provide_problems(): array {
		return array(
			'switched off'     => array( 'firewall', array( 'enabled' => false ), 'firewall_disabled' ),
			'kill switch'      => array( 'worker', array( 'kill_switch' => true ), 'worker_kill_switch' ),
			'no worker'        => array( 'worker', array( 'installed' => false ), 'worker_missing' ),
			'stale worker'     => array( 'worker', array( 'outdated' => true ), 'worker_outdated' ),
			'silent worker'    => array( 'worker', array( 'last_seen' => 0 ), 'worker_silent' ),
			'install failed'   => array( 'worker', array( 'last_attempt' => array( 'success' => false, 'message' => 'x' ) ), 'worker_install_failed' ),
			'mu not writable'  => array( 'worker', array( 'mu_dir_writable' => false ), 'mu_dir_not_writable' ),
			'probe failed'     => array( 'storage', array( 'probe' => array( 'ok' => false, 'message' => 'x' ) ), 'storage_probe_failed' ),
			'file dir'         => array( 'storage', array( 'backend' => 'file', 'file_dir_writable' => false ), 'file_cache_not_writable' ),
			'private ip'       => array( 'client_ip', array( 'routable' => false ), 'ip_non_routable' ),
			'ignored header'   => array( 'client_ip', array( 'forwarded_headers' => array( array( 'name' => 'X-Forwarded-For', 'value' => '1.2.3.4' ) ) ), 'proxy_headers_ignored' ),
			'stale geo cache'  => array( 'geo', array( 'countries' => array( array( 'cc' => 'CN', 'stale' => true ) ) ), 'geo_cache_stale' ),
			'pending alerts'   => array( 'alerts', array( 'pending' => 2 ), 'alerts_pending' ),
			'mail error'       => array( 'alerts', array( 'mail_error' => true ), 'alerts_mail_error' ),
		);
	}

	public function test_a_trusted_proxy_header_is_not_flagged(): void {
		$status = self::healthy(
			'client_ip',
			array(
				'trusted_proxy_match' => true,
				'forwarded_headers'   => array( array( 'name' => 'X-Forwarded-For', 'value' => '1.2.3.4' ) ),
			)
		);

		$this->assertNotContains( 'proxy_headers_ignored', self::codes( $status ) );
	}

	/**
	 * Behind Cloudflare the country header is used; the CIDR lists do not
	 * matter.
	 */
	public function test_a_stale_geo_cache_behind_cloudflare_is_not_flagged(): void {
		$status                            = self::healthy( 'geo', array( 'countries' => array( array( 'cc' => 'CN', 'stale' => true ) ) ) );
		$status['client_ip']['cloudflare'] = true;

		$this->assertNotContains( 'geo_cache_stale', self::codes( $status ) );
	}
}
