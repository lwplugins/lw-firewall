<?php
/**
 * Tests for the one-time blocked-bot default refresh.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Upgrade;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Upgrade\BotDefaultsMigration;

/**
 * @covers \LightweightPlugins\Firewall\Upgrade\BotDefaultsMigration
 */
final class BotDefaultsMigrationTest extends MonkeyTestCase {

	/**
	 * Options written during the test run, keyed by option name.
	 *
	 * @var array<string, mixed>
	 */
	private array $written = [];

	/**
	 * The blocked_bots list as shipped up to 1.5.7.
	 *
	 * @return array<int, string>
	 */
	private function legacy_list(): array {
		return array(
			'meta-externalagent',
			'meta-externalfetcher',
			'gptbot',
			'chatgpt-user',
			'claudebot',
			'claude-web',
			'bytespider',
			'amazonbot',
			'anthropic-ai',
			'cohere-ai',
			'diffbot',
			'perplexitybot',
			'youbot',
			'petalbot',
			'semrushbot',
			'ahrefsbot',
			'dotbot',
			'mj12bot',
			'barkrowler',
			'dataforseobot',
		);
	}

	/**
	 * Stub get_option/update_option around an in-memory option store.
	 *
	 * @param array<string, mixed> $stored Initial option values.
	 * @return void
	 */
	private function stub_options( array $stored ): void {
		$this->written = array();

		Functions\when( 'get_option' )->alias(
			function ( $name, $fallback = false ) use ( $stored ) {
				return array_key_exists( $name, $this->written )
					? $this->written[ $name ]
					: ( $stored[ $name ] ?? $fallback );
			}
		);

		Functions\when( 'update_option' )->alias(
			function ( $name, $value ) {
				$this->written[ $name ] = $value;

				return true;
			}
		);
	}

	public function test_untouched_list_is_replaced_with_the_current_defaults(): void {
		$this->stub_options(
			array(
				Options::OPTION_NAME => array(
					'rate_limit'   => 99,
					'blocked_bots' => $this->legacy_list(),
				),
			)
		);

		BotDefaultsMigration::maybe_apply();

		$saved = $this->written[ Options::OPTION_NAME ];

		$this->assertSame( Options::get_defaults()['blocked_bots'], $saved['blocked_bots'] );
		$this->assertSame( 99, $saved['rate_limit'], 'Unrelated settings must survive the rewrite.' );
	}

	/**
	 * A textarea round-trip can reorder or re-case entries without changing
	 * what is blocked; that still counts as untouched.
	 */
	public function test_reordered_and_recased_legacy_list_still_counts_as_untouched(): void {
		$list = array_map( 'strtoupper', $this->legacy_list() );
		sort( $list );

		$this->stub_options(
			array( Options::OPTION_NAME => array( 'blocked_bots' => $list ) )
		);

		BotDefaultsMigration::maybe_apply();

		$this->assertSame(
			Options::get_defaults()['blocked_bots'],
			$this->written[ Options::OPTION_NAME ]['blocked_bots']
		);
	}

	public function test_an_edited_list_is_left_alone(): void {
		$list   = $this->legacy_list();
		$list[] = 'my-own-scraper';

		$this->stub_options(
			array( Options::OPTION_NAME => array( 'blocked_bots' => $list ) )
		);

		BotDefaultsMigration::maybe_apply();

		$this->assertArrayNotHasKey( Options::OPTION_NAME, $this->written );
	}

	/**
	 * Removing a single entry is an expressed intent — keeping the rest of the
	 * legacy list must not be undone by the migration.
	 */
	public function test_a_list_with_one_entry_removed_is_left_alone(): void {
		$list = array_values( array_diff( $this->legacy_list(), array( 'ahrefsbot' ) ) );

		$this->stub_options(
			array( Options::OPTION_NAME => array( 'blocked_bots' => $list ) )
		);

		BotDefaultsMigration::maybe_apply();

		$this->assertArrayNotHasKey( Options::OPTION_NAME, $this->written );
	}

	public function test_it_runs_only_once(): void {
		$this->stub_options(
			array(
				BotDefaultsMigration::REVISION_OPTION => 1,
				Options::OPTION_NAME                  => array( 'blocked_bots' => $this->legacy_list() ),
			)
		);

		BotDefaultsMigration::maybe_apply();

		$this->assertSame( array(), $this->written );
	}

	public function test_a_fresh_install_without_stored_settings_is_only_stamped(): void {
		$this->stub_options( array() );

		BotDefaultsMigration::maybe_apply();

		$this->assertSame(
			array( BotDefaultsMigration::REVISION_OPTION => 1 ),
			$this->written
		);
	}
}
