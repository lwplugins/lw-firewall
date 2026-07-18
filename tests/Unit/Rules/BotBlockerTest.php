<?php
/**
 * Regression tests for bot User-Agent blocking.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Rules\BotBlocker;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\BotBlocker
 */
final class BotBlockerTest extends MonkeyTestCase {

	/**
	 * @param array<int, string> $blocked_bots Stored bot list.
	 * @return void
	 */
	private function stub_bots( array $blocked_bots ): void {
		Functions\when( 'get_option' )->justReturn( array( 'blocked_bots' => $blocked_bots ) );
	}

	public function test_matches_a_configured_bot(): void {
		$this->stub_bots( array( 'gptbot' ) );

		$this->assertTrue( BotBlocker::is_blocked( 'Mozilla/5.0 (compatible; GPTBot/1.0)' ) );
	}

	public function test_clean_user_agent_passes(): void {
		$this->stub_bots( array( 'gptbot', 'ahrefsbot' ) );

		$this->assertFalse( BotBlocker::is_blocked( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' ) );
	}

	public function test_empty_user_agent_is_not_blocked(): void {
		$this->stub_bots( array( 'gptbot' ) );

		$this->assertFalse( BotBlocker::is_blocked( '' ) );
	}

	/**
	 * A single blank list entry must NOT match every request (str_contains with
	 * an empty needle is always true → a full-site outage).
	 */
	public function test_empty_list_entry_does_not_block_everything(): void {
		$this->stub_bots( array( '', 'gptbot' ) );

		$this->assertFalse( BotBlocker::is_blocked( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' ) );
	}

	public function test_whitespace_only_entry_is_ignored(): void {
		$this->stub_bots( array( '   ', 'gptbot' ) );

		$this->assertFalse( BotBlocker::is_blocked( 'Mozilla/5.0 legitimate client' ) );
	}
}
