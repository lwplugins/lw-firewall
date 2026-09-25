<?php
/**
 * Tests for writing the real plugin directory into the installed worker.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit;

use LightweightPlugins\Firewall\WorkerTemplate;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\WorkerTemplate
 */
final class WorkerTemplateTest extends TestCase {

	private static function source(): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/worker/lw-firewall-worker.php' );
	}

	/**
	 * The bug: the worker looked for WP_PLUGIN_DIR . '/lw-firewall/', so a
	 * renamed plugin directory produced a worker that installed but never ran.
	 */
	public function test_the_worker_source_has_no_hardcoded_plugin_path(): void {
		$this->assertStringNotContainsString( "WP_PLUGIN_DIR . '/lw-firewall/", self::source() );
	}

	public function test_renders_the_real_directory_into_the_worker(): void {
		$rendered = WorkerTemplate::render( self::source(), 'my-firewall' );

		$this->assertStringContainsString( "define( 'LW_FIREWALL_WORKER_DIR', 'my-firewall' );", $rendered );
	}

	public function test_rendering_keeps_the_version_guard_and_the_manifest(): void {
		$rendered = WorkerTemplate::render( self::source(), 'my-firewall' );

		$this->assertStringContainsString( "define( 'LW_FIREWALL_WORKER_VERSION',", $rendered );
		$this->assertStringContainsString( "'Rules/AutoBanner.php',", $rendered );
		$this->assertStringContainsString( 'LW_FIREWALL_WORKER_VERSION !== $data[\'Version\']', $rendered );
	}

	public function test_the_unrendered_source_falls_back_to_the_default_directory(): void {
		$this->assertStringContainsString( "define( 'LW_FIREWALL_WORKER_DIR', 'lw-firewall' );", self::source() );
	}

	/**
	 * The directory name is written into PHP source, so anything that could
	 * break out of the string literal must never reach it.
	 *
	 * @dataProvider provide_unsafe_directories
	 *
	 * @param string $dir Candidate directory name.
	 */
	public function test_an_unsafe_directory_name_falls_back_to_the_default( string $dir ): void {
		$rendered = WorkerTemplate::render( self::source(), $dir );

		$this->assertStringContainsString( "define( 'LW_FIREWALL_WORKER_DIR', 'lw-firewall' );", $rendered );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_unsafe_directories(): array {
		return [
			'empty'          => [ '' ],
			'dot'            => [ '.' ],
			'parent'         => [ '..' ],
			'quote'          => [ "x'); phpinfo(); //" ],
			'slash'          => [ 'a/b' ],
			'backslash'      => [ 'a\\b' ],
			'dollar'         => [ '$x' ],
			'newline'        => [ "a\nb" ],
		];
	}

	/**
	 * @dataProvider provide_basenames
	 *
	 * @param string $basename plugin_basename() of the main file.
	 * @param string $expected Directory name.
	 */
	public function test_derives_the_directory_from_the_plugin_basename( string $basename, string $expected ): void {
		$this->assertSame( $expected, WorkerTemplate::dir_from_basename( $basename ) );
	}

	/**
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function provide_basenames(): array {
		return [
			'standard'            => [ 'lw-firewall/lw-firewall.php', 'lw-firewall' ],
			'renamed directory'   => [ 'lw-firewall-main/lw-firewall.php', 'lw-firewall-main' ],
			'no directory'        => [ 'lw-firewall.php', 'lw-firewall' ],
			'unsafe directory'    => [ "x'y/lw-firewall.php", 'lw-firewall' ],
		];
	}
}
