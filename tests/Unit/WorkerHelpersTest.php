<?php
/**
 * Tests for the shared worker helper functions (rate-limit exemptions).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Covers includes/helpers.php (login-cookie detection, cron loopback, and the
 * scoped logged-in rate-limit bucket).
 */
final class WorkerHelpersTest extends TestCase {

	protected function tearDown(): void {
		$_COOKIE = array();
		parent::tearDown();
	}

	// --- lw_firewall_has_login_cookie() ---

	public function test_no_cookies_is_not_logged_in(): void {
		$_COOKIE = array();
		$this->assertFalse( \lw_firewall_has_login_cookie() );
	}

	public function test_well_formed_login_cookie_is_detected(): void {
		$_COOKIE = array( 'wordpress_logged_in_abc' => 'admin|1751000000|token|hmac' );
		$this->assertTrue( \lw_firewall_has_login_cookie() );
	}

	public function test_malformed_login_cookie_is_not_detected(): void {
		$_COOKIE = array( 'wordpress_logged_in_abc' => 'garbage' );
		$this->assertFalse( \lw_firewall_has_login_cookie() );
	}

	public function test_unrelated_cookie_is_not_a_login_cookie(): void {
		$_COOKIE = array( 'some_other' => 'a|b|c|d' );
		$this->assertFalse( \lw_firewall_has_login_cookie() );
	}

	// --- lw_firewall_is_cron_loopback() ---

	public function test_cron_loopback_with_marker_is_recognised(): void {
		$this->assertTrue( \lw_firewall_is_cron_loopback( \lw_firewall_parse_uri( '/wp-cron.php?doing_wp_cron=1751000000.1' ) ) );
	}

	public function test_bare_wp_cron_is_not_a_loopback(): void {
		$this->assertFalse( \lw_firewall_is_cron_loopback( \lw_firewall_parse_uri( '/wp-cron.php' ) ) );
	}

	public function test_marker_smuggled_onto_another_endpoint_is_not_a_loopback(): void {
		$this->assertFalse( \lw_firewall_is_cron_loopback( \lw_firewall_parse_uri( '/wp-json/wc/v3/orders?doing_wp_cron=1' ) ) );
	}

	/**
	 * The real smuggle: naming the cron endpoint inside the query string. The
	 * old substring check saw "/wp-cron.php" plus the marker anywhere in the
	 * URI and exempted the request from every limit.
	 */
	public function test_the_cron_path_in_a_query_argument_is_not_a_loopback(): void {
		$this->assertFalse(
			\lw_firewall_is_cron_loopback(
				\lw_firewall_parse_uri( '/wp-json/acme/v1/submit?next=/wp-cron.php&doing_wp_cron=x' )
			)
		);
	}

	// --- lw_firewall_parse_uri() ---

	/**
	 * @dataProvider provide_uris
	 *
	 * @param string $uri  Raw request URI.
	 * @param string $path Path the firewall should classify on.
	 */
	public function test_parses_the_path_apart_from_the_query( string $uri, string $path ): void {
		$this->assertSame( $path, \lw_firewall_parse_uri( $uri )['path'] );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function provide_uris(): array {
		return array(
			'plain'                => array( '/wp-login.php', '/wp-login.php' ),
			'query ignored'        => array( '/some-page?redirect=/wp-login.php', '/some-page' ),
			'trailing slash'       => array( '/wp-cron.php/', '/wp-cron.php' ),
			'double slash'         => array( '//wp-cron.php', '/wp-cron.php' ),
			'percent encoded'      => array( '/wp-%63ron.php', '/wp-cron.php' ),
			'subdirectory install' => array( '/blog/wp-login.php', '/blog/wp-login.php' ),
			'root'                 => array( '/', '/' ),
		);
	}

	public function test_reads_query_arguments(): void {
		$parsed = \lw_firewall_parse_uri( '/x?rest_route=/wp/v2/posts&page=2' );

		$this->assertSame( '/wp/v2/posts', $parsed['args']['rest_route'] );
		$this->assertSame( '2', $parsed['args']['page'] );
	}

	// --- lw_firewall_login_exempt_reason() ---

	/**
	 * The security-critical property: only REST and filter may use the higher
	 * logged-in bucket. login/xmlrpc/cron must NEVER be exempt, so a forged
	 * cookie cannot weaken brute-force / abuse protection.
	 *
	 * @dataProvider provide_reasons
	 */
	public function test_only_rest_and_filter_are_login_exempt( string $reason, bool $expected ): void {
		$this->assertSame( $expected, \lw_firewall_login_exempt_reason( $reason ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function provide_reasons(): array {
		return array(
			'rest'   => array( 'rest', true ),
			'filter' => array( 'filter', true ),
			'login'  => array( 'login', false ),
			'xmlrpc' => array( 'xmlrpc', false ),
			'cron'   => array( 'cron', false ),
		);
	}

	// --- lw_firewall_loggedin_limit() ---

	public function test_loggedin_limit_is_ten_times_the_base_by_default(): void {
		$this->assertSame( 300, \lw_firewall_loggedin_limit( null, array( 'rate_limit' => 30 ) ) );
	}

	public function test_loggedin_limit_uses_a_custom_endpoint_limit(): void {
		$this->assertSame( 500, \lw_firewall_loggedin_limit( 50, array( 'rate_limit' => 30 ) ) );
	}

	public function test_loggedin_limit_never_drops_below_the_factor(): void {
		$this->assertSame( 10, \lw_firewall_loggedin_limit( 0, array() ) );
	}
}
