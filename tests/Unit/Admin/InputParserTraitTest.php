<?php
/**
 * Tests that the settings form never persists a wp-config.php pinned bot list.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin;

use LightweightPlugins\Firewall\Admin\InputParserTrait;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

/**
 * Exposes the trait's parser the way SettingsSaver uses it.
 */
final class InputParserHost {
	use InputParserTrait;

	/**
	 * @param array<string, mixed> $post_data Form data.
	 * @return array<int, string>
	 */
	public static function bots( array $post_data ): array {
		return self::parse_blocked_bots( $post_data );
	}
}

/**
 * @covers \LightweightPlugins\Firewall\Admin\InputParserTrait
 */
final class InputParserTraitTest extends MonkeyTestCase {

	/**
	 * With the field absent from the form, the saved value must be the one in
	 * the database — not the constant, which would then outlive its removal
	 * from wp-config.php.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_a_missing_bot_field_falls_back_to_the_stored_list_not_the_pinned_one(): void {
		define( 'LW_FIREWALL_BLOCKED_BOTS', [ 'pinnedbot' ] );
		OptionStore::install( [ 'lw_firewall' => [ 'blocked_bots' => [ 'storedbot' ] ] ] );

		$this->assertSame( [ 'storedbot' ], InputParserHost::bots( [] ) );
	}
}
