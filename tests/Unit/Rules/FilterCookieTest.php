<?php
/**
 * Tests for the filter visitor-cookie rule.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\FilterCookie;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\FilterCookie
 */
final class FilterCookieTest extends TestCase {

	protected function tearDown(): void {
		$_COOKIE = [];
		parent::tearDown();
	}

	public function test_visitor_cookie_is_recognised(): void {
		$_COOKIE = [ 'lwfw_v' => '1' ];
		$this->assertTrue( FilterCookie::has_cookie() );
	}

	public function test_missing_cookie_is_not_recognised(): void {
		$_COOKIE = [ 'other' => '1' ];
		$this->assertFalse( FilterCookie::has_cookie() );
	}

	public function test_cookie_with_another_value_is_not_recognised(): void {
		$_COOKIE = [ 'lwfw_v' => 'x' ];
		$this->assertFalse( FilterCookie::has_cookie() );
	}

	/**
	 * @dataProvider provide_methods
	 *
	 * @param string $method   Request method.
	 * @param bool   $expected Whether the challenge may answer it.
	 */
	public function test_challenges_only_safe_methods( string $method, bool $expected ): void {
		$this->assertSame( $expected, FilterCookie::applies_to_method( $method ) );
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function provide_methods(): array {
		return [
			'GET'  => [ 'GET', true ],
			'HEAD' => [ 'head', true ],
			'POST' => [ 'POST', false ],
		];
	}

	public function test_challenge_escapes_the_fallback_link(): void {
		$html = FilterCookie::challenge_html( '/shop/"><script>x</script>' );

		$this->assertStringNotContainsString( '"><script>x', $html );
	}

	public function test_challenge_sets_the_cookie_and_reloads_the_same_url(): void {
		$html = FilterCookie::challenge_html( '/shop/' );

		$this->assertStringContainsString( 'location.replace(location.href)', $html );
	}

	public function test_challenge_stops_reloading_when_the_marker_is_already_set(): void {
		$html = FilterCookie::challenge_html( '/shop/' );

		$this->assertMatchesRegularExpression( '/lwfw_c=1\/\.test\(d\.cookie\)\)\{f\(\);return;\}/', $html );
	}

	public function test_page_script_renews_the_visitor_cookie(): void {
		$this->assertStringContainsString( 'lwfw_v=1; max-age=2592000', FilterCookie::page_script() );
	}
}
