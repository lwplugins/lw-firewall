<?php
/**
 * Tests that Site Manager blacklist edits never persist wp-config.php pins.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\SiteManager;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rules\IpMatcher;
use LightweightPlugins\Firewall\SiteManager\FirewallService;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

/**
 * @covers \LightweightPlugins\Firewall\SiteManager\FirewallService
 */
final class FirewallServiceTest extends MonkeyTestCase {

	private OptionStore $options;

	/**
	 * rate_window is pinned to 5 in "wp-config.php" (the same constant
	 * OptionsOverrideTest uses; constants are process-global), while the
	 * database holds 999.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'LW_FIREWALL_RATE_WINDOW' ) ) {
			define( 'LW_FIREWALL_RATE_WINDOW', 5 );
		}

		Functions\stubTranslationFunctions();

		$this->options = OptionStore::install(
			[
				'lw_firewall' => [
					'rate_window'  => 999,
					'ip_blacklist' => [ '198.51.100.1' ],
				],
			]
		);
	}

	public function test_blocking_an_ip_keeps_the_stored_value_of_a_pinned_setting(): void {
		FirewallService::block_ip( [ 'ip' => '203.0.113.9' ] );

		$this->assertSame( 999, $this->options->data['lw_firewall']['rate_window'] );
	}

	public function test_blocking_an_ip_adds_it_to_the_stored_blacklist(): void {
		FirewallService::block_ip( [ 'ip' => '203.0.113.9' ] );

		$this->assertSame( [ '198.51.100.1', '203.0.113.9' ], $this->options->data['lw_firewall']['ip_blacklist'] );
	}

	public function test_unblocking_an_ip_keeps_the_stored_value_of_a_pinned_setting(): void {
		FirewallService::unblock_ip( [ 'ip' => '198.51.100.1' ] );

		$this->assertSame( 999, $this->options->data['lw_firewall']['rate_window'] );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function malformed_entries(): array {
		return [
			'text prefix'      => [ '198.51.100.0/foo' ],
			'negative prefix'  => [ '198.51.100.0/-1' ],
			'empty prefix'     => [ '198.51.100.0/' ],
			'trailing garbage' => [ '198.51.100.0/24foo' ],
			'ipv4 too wide'    => [ '198.51.100.0/33' ],
			'ipv6 too wide'    => [ '2001:db8::/129' ],
		];
	}

	/**
	 * @dataProvider malformed_entries
	 */
	public function test_blocking_a_malformed_entry_errors_and_saves_nothing( string $entry ): void {
		$result = FirewallService::block_ip( [ 'ip' => $entry ] );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( [ '198.51.100.1' ], $this->options->data['lw_firewall']['ip_blacklist'] );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function valid_entries(): array {
		return [
			'ipv4 range'   => [ '198.51.100.0/24' ],
			'single ipv4'  => [ '198.51.100.7' ],
			'ipv6 range'   => [ '2001:db8::/32' ],
		];
	}

	/**
	 * @dataProvider valid_entries
	 */
	public function test_blocking_a_valid_entry_saves_it_and_it_matches( string $entry ): void {
		$result = FirewallService::block_ip( [ 'ip' => $entry ] );

		$this->assertIsArray( $result );
		$this->assertTrue( $result['success'] );

		$stored = $this->options->data['lw_firewall']['ip_blacklist'];
		$this->assertContains( $entry, $stored );

		$probe = str_contains( $entry, ':' ) ? '2001:db8::1' : '198.51.100.7';
		$this->assertTrue( IpMatcher::matches( $probe, $stored ) );
	}
}
