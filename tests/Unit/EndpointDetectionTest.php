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
			'woo attribute filter'         => [ '/?filter_hossz-mm=10&query_type_hossz-mm=or', 'filter' ],
			'woo attribute on shop path'   => [ '/shop/?filter_atmero=20', 'filter' ],
			'woo price filter'             => [ '/shop/?min_price=10&max_price=90', 'filter' ],
			'woo rating filter'            => [ '/shop/?rating_filter=4', 'filter' ],
			'woo block stock filter'       => [ '/shop/?filter_stock_status=instock', 'filter' ],
			'woo block category filter'    => [ '/shop/?categories=shoes', 'filter' ],
			'plain query is not a filter'  => [ '/shop/?orderby=price', null ],
			'bare prefix is not a filter'  => [ '/?filter_=1', null ],
			'REST with filter-like args'   => [ '/wp-json/wp/v2/posts?categories=5', null ],
			'rest_route with filter args'  => [ '/?rest_route=/wc/store/products&min_price=1', null ],
			'admin list filter action'     => [ '/wp-admin/edit.php?filter_action=Filter', null ],
		];
	}

	public function test_add_to_cart_link_is_classified_when_protected(): void {
		$options = self::OPTIONS + [ 'add_to_cart_require_cookie' => true ];

		$this->assertSame( 'cart', \lw_firewall_detect_type( '/termek-cimke/dn20/?add-to-cart=22853', $options )[0] );
	}

	public function test_add_to_cart_link_is_not_classified_when_unprotected(): void {
		$this->assertNull( \lw_firewall_detect_type( '/termek/x/?add-to-cart=5332', self::OPTIONS )[0] );
	}

	public function test_add_to_cart_link_is_not_classified_without_woocommerce(): void {
		$options = self::OPTIONS + [ 'add_to_cart_require_cookie' => true ];

		$this->assertNull( \lw_firewall_detect_type( '/termek/x/?add-to-cart=5332', $options, false )[0] );
	}

	public function test_filters_are_not_classified_without_woocommerce(): void {
		$this->assertNull( \lw_firewall_detect_type( '/shop/?filter_color=red', self::OPTIONS, false )[0] );
	}

	public function test_a_subdirectory_cron_loopback_is_recognised(): void {
		$this->assertTrue( \lw_firewall_is_cron_loopback( \lw_firewall_parse_uri( '/blog/wp-cron.php?doing_wp_cron=1751000000.1' ) ) );
	}

	public function test_a_subdirectory_cron_loopback_is_not_throttled(): void {
		$this->assertNull( \lw_firewall_detect_type( '/blog/wp-cron.php?doing_wp_cron=1751000000.1', self::OPTIONS )[0] );
	}
}
