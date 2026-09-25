<?php
/**
 * Tests for the worker install attempt mapping.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Status;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Admin\Status\WorkerState;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Status\WorkerState
 * @covers \LightweightPlugins\Firewall\Admin\WorkerInstallReasons
 */
final class WorkerStateTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubTranslationFunctions();
	}

	/**
	 * Regression: the Status tab showed the raw code (mu_dir_not_writable).
	 */
	public function test_a_failed_attempt_carries_a_sentence_not_the_code(): void {
		$attempt = WorkerState::attempt(
			array(
				'success' => false,
				'error'   => 'mu_dir_not_writable',
				'time'    => 100,
			),
			160
		);

		$this->assertSame(
			array(
				'success' => false,
				'code'    => 'mu_dir_not_writable',
				'message' => 'The mu-plugins directory is not writable.',
				'time'    => 100,
				'age'     => 60,
			),
			$attempt
		);
	}

	public function test_an_unknown_code_gets_a_generic_sentence(): void {
		$attempt = WorkerState::attempt( array( 'success' => false, 'error' => 'weird', 'time' => 1 ), 1 );

		$this->assertSame( 'Unknown install error.', $attempt['message'] );
	}

	public function test_no_attempt_is_null(): void {
		$this->assertNull( WorkerState::attempt( null, 1 ) );
	}
}
