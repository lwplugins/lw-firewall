<?php
/**
 * Tests that Site Manager blacklist edits never persist wp-config.php pins.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\SiteManager;

use Brain\Monkey\Functions;
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
}
