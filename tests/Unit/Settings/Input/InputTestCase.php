<?php
/**
 * Base case for the settings input layer tests.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Settings\Input;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * Stubs the translation functions and is_email() the parsers use.
 */
abstract class InputTestCase extends MonkeyTestCase {

	/**
	 * Stub the WordPress functions every parser may reach.
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();

		Functions\stubTranslationFunctions();
		Functions\when( 'is_email' )->alias(
			static fn ( string $email ) => false !== filter_var( $email, FILTER_VALIDATE_EMAIL ) ? $email : false
		);
	}
}
