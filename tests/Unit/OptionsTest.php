<?php
/**
 * Tests for the security-critical country-code validators on Options.
 *
 * These validators gate every sink that turns a country code into a file path
 * (GeoDetector include, CidrUpdater cache write) or an .htaccess directive.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use LightweightPlugins\Firewall\Options;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Options
 */
final class OptionsTest extends TestCase {

	public function test_accepts_a_valid_two_letter_code(): void {
		$this->assertTrue( Options::is_country_code( 'CN' ) );
		$this->assertTrue( Options::is_country_code( 'ru' ) );
	}

	/**
	 * @dataProvider provide_malicious_codes
	 */
	public function test_rejects_non_country_code( string $code ): void {
		$this->assertFalse( Options::is_country_code( $code ) );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_malicious_codes(): array {
		return array(
			'path traversal'    => array( '../../../../wp-content/uploads/x' ),
			'newline injection' => array( "XX\nRewriteRule .* http://evil/ [R]" ),
			'too long'          => array( 'CHN' ),
			'too short'         => array( 'C' ),
			'digits'            => array( '12' ),
			'empty'             => array( '' ),
			'slash'             => array( 'a/' ),
		);
	}

	public function test_sanitize_keeps_only_valid_uppercased_unique_codes(): void {
		// 'cn'/'CN' collapse to CN; the traversal, newline-injected and
		// wrong-length entries are dropped entirely; 'ru' → RU.
		$result = Options::sanitize_country_codes(
			array( 'cn', 'CN', '../etc/passwd', "XX\nevil", 'ru', 'BAD1' )
		);

		$this->assertSame( array( 'CN', 'RU' ), $result );
	}

	public function test_sanitize_drops_a_traversal_only_list(): void {
		$this->assertSame(
			array(),
			Options::sanitize_country_codes( array( '../../../../wp-content/uploads/2024/01/avatar' ) )
		);
	}
}
