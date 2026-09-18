<?php
/**
 * Regression tests for bot User-Agent blocking.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Options;
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

	/**
	 * The shipped defaults must let through the AI agents that fetch a page on
	 * a human's behalf, or that cite and link back. Substring matching makes
	 * this easy to break by accident: a future entry such as 'searchbot' or
	 * 'openai.com' would silently swallow these User-Agents.
	 *
	 * @dataProvider provide_agents_that_must_pass
	 */
	public function test_shipped_defaults_let_referral_agents_through( string $user_agent ): void {
		$this->stub_bots( Options::get_defaults()['blocked_bots'] );

		$this->assertFalse(
			BotBlocker::is_blocked( $user_agent ),
			'The default bot list must not block: ' . $user_agent
		);
	}

	/**
	 * Verbatim User-Agent strings from the vendors' own crawler documentation.
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function provide_agents_that_must_pass(): array {
		return array(
			'OAI-SearchBot'         => array( 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36; compatible; OAI-SearchBot/1.4; +https://openai.com/searchbot' ),
			'ChatGPT-User'          => array( 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot' ),
			'ClaudeBot'             => array( 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)' ),
			'Claude-User'           => array( 'Mozilla/5.0 (compatible; Claude-User/1.0; +Claude-User@anthropic.com)' ),
			'Claude-SearchBot'      => array( 'Mozilla/5.0 (compatible; Claude-SearchBot/1.0; +Claude-SearchBot@anthropic.com)' ),
			'PerplexityBot'         => array( 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)' ),
			'Perplexity-User'       => array( 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)' ),
			'meta-externalfetcher'  => array( 'meta-externalfetcher/1.1' ),
			'Googlebot'             => array( 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' ),
			'Bingbot'               => array( 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' ),
		);
	}

	/**
	 * The other side of the contract: the crawlers we still ship as blocked
	 * must keep matching.
	 *
	 * @dataProvider provide_agents_that_must_be_blocked
	 */
	public function test_shipped_defaults_still_block_the_scrapers( string $user_agent ): void {
		$this->stub_bots( Options::get_defaults()['blocked_bots'] );

		$this->assertTrue(
			BotBlocker::is_blocked( $user_agent ),
			'The default bot list must still block: ' . $user_agent
		);
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_agents_that_must_be_blocked(): array {
		return array(
			'GPTBot'             => array( 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot' ),
			'meta-externalagent' => array( 'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)' ),
			'Bytespider'         => array( 'Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)' ),
			'AhrefsBot'          => array( 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)' ),
			'SemrushBot'         => array( 'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)' ),
			'MJ12bot'            => array( 'Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)' ),
			'DataForSeoBot'      => array( 'Mozilla/5.0 (compatible; DataForSeoBot/1.0; +https://dataforseo.com/dataforseo-bot)' ),
		);
	}
}
