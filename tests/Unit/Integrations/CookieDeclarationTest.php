<?php
/**
 * Tests for the LW Cookie declaration of the visitor cookies.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Integrations;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Integrations\CookieDeclaration;
use LightweightPlugins\Firewall\Rules\FilterCookie;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Integrations\CookieDeclaration
 */
final class CookieDeclarationTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubs( [ '__' => static fn ( string $t ): string => $t ] );
	}

	public function test_both_visitor_cookies_are_declared_as_necessary(): void {
		$result = CookieDeclaration::register( [] );

		$this->assertCount( 2, $result );
		$this->assertSame( [ FilterCookie::COOKIE, FilterCookie::MARKER ], array_column( $result, 'name' ) );
		foreach ( $result as $cookie ) {
			$this->assertSame( 'necessary', $cookie['category'] );
			$this->assertSame( 'LW Firewall', $cookie['provider'] );
			$this->assertNotSame( '', $cookie['purpose'] );
		}
	}

	public function test_durations_match_the_real_cookies(): void {
		$result = CookieDeclaration::register( [] );

		$this->assertSame( 'persistent', $result[0]['type'] );
		$this->assertSame( '30 days', $result[0]['duration'] );
		$this->assertSame( 'persistent', $result[1]['type'] );
		$this->assertSame( '1 minute', $result[1]['duration'] );
	}

	public function test_existing_entries_are_kept_first(): void {
		$existing = [ 'name' => 'other', 'category' => 'marketing' ];
		$result   = CookieDeclaration::register( [ $existing ] );

		$this->assertCount( 3, $result );
		$this->assertSame( $existing, $result[0] );
	}
}
