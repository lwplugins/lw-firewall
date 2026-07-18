<?php
/**
 * Regression tests for the rate-limit redirect target sanitisation.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\RateLimiter;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\RateLimiter
 */
final class RateLimiterTest extends TestCase {

	public function test_strips_the_query_string(): void {
		$this->assertSame( '/shop/', RateLimiter::safe_redirect_path( '/shop/?filter_color=red' ) );
	}

	/**
	 * A request line beginning with "//" must not become a protocol-relative
	 * (open) redirect.
	 */
	public function test_collapses_leading_slashes(): void {
		$this->assertSame( '/evil.example/', RateLimiter::safe_redirect_path( '//evil.example/?x=1' ) );
		$this->assertSame( '/evil.example/', RateLimiter::safe_redirect_path( '///evil.example/' ) );
	}

	public function test_roots_a_bare_uri(): void {
		$this->assertSame( '/', RateLimiter::safe_redirect_path( '/' ) );
	}
}
