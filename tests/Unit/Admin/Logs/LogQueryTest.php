<?php
/**
 * Tests for the log query.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Logs;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Admin\Logs\LogQuery;
use LightweightPlugins\Firewall\Admin\Logs\LogReasons;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Logs\LogQuery
 * @covers \LightweightPlugins\Firewall\Admin\Logs\LogReasons
 */
final class LogQueryTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubTranslationFunctions();
	}

	/**
	 * @return array<int, array<string, string>>
	 */
	private static function entries(): array {
		return array(
			array( 'ip' => '1.1.1.1', 'reason' => 'bot_blocked', 'ua' => 'GPTBot/1.0', 'url' => '/a', 'time' => '2026-09-25 10:00:03' ),
			array( 'ip' => '2.2.2.2', 'reason' => 'reset_user (user 7)', 'ua' => 'curl', 'url' => '/wp-login.php', 'time' => '2026-09-25 10:00:02' ),
			array( 'ip' => '3.3.3.3', 'reason' => 'bot_blocked', 'ua' => 'Bytespider', 'url' => '/b', 'time' => '2026-09-25 10:00:01' ),
		);
	}

	public function test_filters_by_the_base_reason_code(): void {
		$result = LogQuery::run( self::entries(), 1, 20, 'reset_user', '' );

		$this->assertSame( array( '2.2.2.2' ), array_column( $result['items'], 'ip' ) );
	}

	public function test_searches_ip_user_agent_and_url_case_insensitively(): void {
		$result = LogQuery::run( self::entries(), 1, 20, '', 'gptbot' );

		$this->assertSame( array( '1.1.1.1' ), array_column( $result['items'], 'ip' ) );
	}

	public function test_pages_the_result(): void {
		$result = LogQuery::run( self::entries(), 2, 2, '', '' );

		$this->assertSame( array( array( '3.3.3.3' ), 3, 2 ), array( array_column( $result['items'], 'ip' ), $result['total'], $result['pages'] ) );
	}

	public function test_an_out_of_range_page_is_clamped(): void {
		$this->assertSame( 1, LogQuery::run( self::entries(), 9, 20, '', '' )['page'] );
	}

	public function test_lists_the_reasons_present_with_labels(): void {
		$this->assertSame(
			array(
				'bot_blocked' => 'Blocked bot',
				'reset_user'  => 'Password reset flood (per account)',
			),
			LogQuery::run( self::entries(), 1, 20, '', '' )['reasons']
		);
	}

	/**
	 * Regression: the Reason column showed raw codes, untranslated.
	 */
	public function test_labels_a_reason_with_a_user_suffix(): void {
		$this->assertSame( 'Password reset flood (per account)', LogReasons::label( 'reset_user (user 7)' ) );
	}

	public function test_an_unknown_reason_is_shown_as_is(): void {
		$this->assertSame( 'something_new', LogReasons::label( 'something_new' ) );
	}

	public function test_skips_malformed_entries(): void {
		$this->assertSame( 0, LogQuery::run( array( 'junk', null ), 1, 20, '', '' )['total'] );
	}
}
