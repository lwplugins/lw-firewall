<?php
/**
 * Tests for the email and user-agent list parsers.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings\Input;

use LightweightPlugins\Firewall\Settings\Input\BotListParser;
use LightweightPlugins\Firewall\Settings\Input\EmailListParser;

/**
 * @covers \LightweightPlugins\Firewall\Settings\Input\EmailListParser
 * @covers \LightweightPlugins\Firewall\Settings\Input\BotListParser
 */
final class TextListParsersTest extends InputTestCase {

	public function test_joins_valid_addresses_into_the_stored_format(): void {
		$this->assertSame(
			'a@example.com, b@example.com',
			EmailListParser::parse( "a@example.com; b@example.com\na@example.com" )->value()
		);
	}

	/**
	 * Regression: invalid addresses were dropped without a word, so a typo
	 * silently sent every alert to the fallback admin email.
	 */
	public function test_rejects_and_reports_an_invalid_address(): void {
		$result = EmailListParser::parse( 'a@example.com, not-an-email' );

		$this->assertFalse( $result->is_valid() );
		$this->assertStringContainsString( 'not-an-email', $result->errors()[0] );
	}

	public function test_an_empty_email_field_is_allowed(): void {
		$this->assertSame( '', EmailListParser::parse( '  ' )->value() );
	}

	public function test_keeps_user_agent_substrings_with_spaces(): void {
		$this->assertSame(
			[ 'gptbot', 'Some Crawler/1.0' ],
			BotListParser::parse( "gptbot\n Some Crawler/1.0 \n\n" )->value()
		);
	}

	public function test_drops_case_insensitive_duplicates(): void {
		$this->assertSame( [ 'GPTBot' ], BotListParser::parse( [ 'GPTBot', 'gptbot' ] )->value() );
	}

	public function test_an_empty_bot_list_is_allowed(): void {
		$this->assertSame( [], BotListParser::parse( '' )->value() );
	}

	public function test_rejects_an_overlong_entry(): void {
		$this->assertFalse( BotListParser::parse( str_repeat( 'a', 201 ) )->is_valid() );
	}
}
