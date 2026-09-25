<?php
/**
 * Tests for endpoint classification (lw_firewall_detect_type / path_is).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Covers the endpoint matcher in includes/helpers.php.
 */
final class EndpointDetectionTest extends TestCase {

	private const OPTIONS = [
		'protect_login'  => true,
		'protect_xmlrpc' => true,
		'protect_cron'   => true,
	];

	protected function setUp(): void {
		parent::setUp();
		$_SERVER['QUERY_STRING'] = '';
	}

	protected function tearDown(): void {
		unset( $_SERVER['QUERY_STRING'] );
		parent::tearDown();
	}

	/**
	 * @dataProvider provide_uris
	 *
	 * @param string      $uri      Request URI.
	 * @param string|null $expected Expected request type.
	 */
	public function test_classifies_the_endpoint( string $uri, ?string $expected ): void {
		$this->assertSame( $expected, \lw_firewall_detect_type( $uri, self::OPTIONS )[0] );
	}

	/**
	 * @return array<string, array{0: string, 1: string|null}>
	 */
	public static function provide_uris(): array {
		return [
			'login'                        => [ '/wp-login.php', 'login' ],
			'login with PATH_INFO'         => [ '/wp-login.php/x', 'login' ],
			'login upper case'             => [ '/WP-LOGIN.PHP', 'login' ],
			'login in subdirectory'        => [ '/blog/wp-login.php', 'login' ],
			'login in subdir + PATH_INFO'  => [ '/blog/wp-login.php/x/y', 'login' ],
			'login with query'             => [ '/wp-login.php?action=lostpassword', 'login' ],
			'xmlrpc'                       => [ '/xmlrpc.php', 'xmlrpc' ],
			'xmlrpc with PATH_INFO'        => [ '/xmlrpc.php/x', 'xmlrpc' ],
			'xmlrpc upper case'            => [ '/XMLRPC.php', 'xmlrpc' ],
			'cron with PATH_INFO'          => [ '/wp-cron.php/x', 'cron' ],
			'cron mixed case'              => [ '/Wp-Cron.php', 'cron' ],
			'look-alike filename prefix'   => [ '/foo-wp-login.php', null ],
			'look-alike filename suffix'   => [ '/wp-login.php.bak', null ],
			'look-alike xmlrpc'            => [ '/notxmlrpc.php/x', null ],
			'endpoint named in the query'  => [ '/page?next=/wp-login.php', null ],
		];
	}

	public function test_a_subdirectory_cron_loopback_is_recognised(): void {
		$this->assertTrue( \lw_firewall_is_cron_loopback( \lw_firewall_parse_uri( '/blog/wp-cron.php?doing_wp_cron=1751000000.1' ) ) );
	}

	public function test_a_subdirectory_cron_loopback_is_not_throttled(): void {
		$this->assertNull( \lw_firewall_detect_type( '/blog/wp-cron.php?doing_wp_cron=1751000000.1', self::OPTIONS )[0] );
	}
}
