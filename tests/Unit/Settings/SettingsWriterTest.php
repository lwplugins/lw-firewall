<?php
/**
 * Tests for the shared settings write path (used by WP-CLI).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings;

use LightweightPlugins\Firewall\Settings\SettingsWriter;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\WritePath;

/**
 * @covers \LightweightPlugins\Firewall\Settings\SettingsWriter
 */
final class SettingsWriterTest extends MonkeyTestCase {

	/**
	 * Regression: `ip|bots|geo|config-items add/remove` started from the
	 * effective list, so a wp-config.php pin was copied into the database the
	 * first time any entry was added or removed.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_a_list_edit_starts_from_the_stored_list_not_the_pinned_one(): void {
		define( 'LW_FIREWALL_BLOCKED_BOTS', array( 'pinnedbot' ) );
		WritePath::install( array( 'blocked_bots' => array( 'storedbot' ) ) );

		$this->assertSame( array( 'storedbot' ), SettingsWriter::stored_list( 'blocked_bots' ) );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_refuses_to_write_a_pinned_key(): void {
		define( 'LW_FIREWALL_IP_BLACKLIST', array( '1.2.3.4' ) );
		$store = WritePath::install( array( 'ip_blacklist' => array() ) );

		SettingsWriter::write_one( 'ip_blacklist', '5.6.7.8' );

		$this->assertSame( array(), $store->data['lw_firewall']['ip_blacklist'] );
	}

	public function test_writes_a_valid_value_and_keeps_the_rest(): void {
		$store = WritePath::install( array( 'rate_window' => 120 ) );

		SettingsWriter::write_one( 'blocked_countries', 'kp, cn' );

		$this->assertSame( array( 'KP', 'CN' ), $store->data['lw_firewall']['blocked_countries'] );
		$this->assertSame( 120, $store->data['lw_firewall']['rate_window'] );
	}

	public function test_returns_the_errors_of_an_invalid_value(): void {
		WritePath::install();

		$this->assertCount( 1, SettingsWriter::write_one( 'blocked_countries', 'Germany' ) );
	}

	public function test_an_unknown_key_is_an_error(): void {
		WritePath::install();

		$this->assertCount( 1, SettingsWriter::write_one( 'nope', '1' ) );
	}
}
