<?php
/**
 * Regression tests for .htaccess geo rule building.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Geo;

use LightweightPlugins\Firewall\Geo\HtaccessWriter;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Geo\HtaccessWriter
 */
final class HtaccessWriterTest extends TestCase {

	public function test_no_rules_when_disabled(): void {
		$this->assertSame( array(), HtaccessWriter::build_rules( false, array( 'CN' ) ) );
	}

	public function test_no_rules_when_no_countries(): void {
		$this->assertSame( array(), HtaccessWriter::build_rules( true, array() ) );
	}

	public function test_builds_rewrite_rules_for_valid_codes(): void {
		$rules = HtaccessWriter::build_rules( true, array( 'CN', 'ru' ) );

		$this->assertSame(
			array(
				'RewriteCond %{HTTP:CF-IPCountry} ^(CN|RU)$ [NC]',
				'RewriteRule .* - [F,L]',
			),
			$rules
		);
	}

	/**
	 * A country code carrying a newline must not survive into the rule lines
	 * (insert_with_markers writes each array element as a raw line, so an
	 * embedded newline would inject arbitrary Apache directives).
	 */
	public function test_strips_directive_injection_from_country_codes(): void {
		$rules = HtaccessWriter::build_rules(
			true,
			array( 'CN', "XX\nRewriteRule .* http://evil.example/ [R=302,L]" )
		);

		$this->assertSame(
			array(
				'RewriteCond %{HTTP:CF-IPCountry} ^(CN)$ [NC]',
				'RewriteRule .* - [F,L]',
			),
			$rules
		);

		foreach ( $rules as $line ) {
			$this->assertStringNotContainsString( "\n", $line );
			$this->assertStringNotContainsString( 'evil.example', $line );
		}
	}
}
