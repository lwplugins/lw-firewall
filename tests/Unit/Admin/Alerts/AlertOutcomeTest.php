<?php
/**
 * Tests for the alert action outcomes.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Alerts;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Admin\Alerts\AlertOutcome;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Alerts\AlertOutcome
 */
final class AlertOutcomeTest extends MonkeyTestCase {

	protected function setUp(): void {
		parent::setUp();
		Functions\stubTranslationFunctions();
	}

	/**
	 * @param array<string, mixed> $overrides Flags to set.
	 * @return array{new: array<int, int>, changes: array<int, mixed>, disabled: bool, seeded: bool, sent: bool, queued: bool}
	 */
	private static function scan( array $overrides = array() ): array {
		return array_merge(
			array(
				'new'      => array(),
				'changes'  => array(),
				'disabled' => false,
				'seeded'   => false,
				'sent'     => false,
				'queued'   => false,
			),
			$overrides
		);
	}

	/**
	 * Regression: with alerts off the scan reported "no new or modified
	 * administrators found".
	 */
	public function test_a_scan_with_alerts_off_says_so(): void {
		$this->assertSame( 'disabled', AlertOutcome::scan( self::scan( array( 'disabled' => true ) ) )['state'] );
	}

	public function test_a_clean_scan_is_clean(): void {
		$this->assertSame( 'clean', AlertOutcome::scan( self::scan() )['state'] );
	}

	/**
	 * Regression: "an alert email was sent" was claimed when the mail
	 * failed and was queued.
	 */
	public function test_a_found_scan_with_a_queued_mail_does_not_claim_it_was_sent(): void {
		$outcome = AlertOutcome::scan( self::scan( array( 'new' => array( 5 ), 'queued' => true ) ) );

		$this->assertSame( array( 'found', false, true ), array( $outcome['state'], $outcome['sent'], $outcome['queued'] ) );
		$this->assertStringContainsString( 'could not be sent', $outcome['message'] );
	}

	public function test_a_found_scan_with_a_sent_mail_reports_it(): void {
		$outcome = AlertOutcome::scan( self::scan( array( 'changes' => array( array( 'id' => 1 ) ), 'sent' => true ) ) );

		$this->assertSame( array( 'found', true ), array( $outcome['state'], $outcome['sent'] ) );
	}

	public function test_a_first_scan_explains_the_silent_snapshot(): void {
		$this->assertStringContainsString( 'recorded silently', AlertOutcome::scan( self::scan( array( 'seeded' => true ) ) )['message'] );
	}

	/**
	 * @dataProvider provide_tests
	 *
	 * @param bool $recipients Has recipients.
	 * @param bool $sent       wp_mail() result.
	 * @param bool $ok         Expected sent flag.
	 */
	public function test_a_test_send_reports_sent_only_when_mailed( bool $recipients, bool $sent, bool $ok ): void {
		$outcome = AlertOutcome::test( $recipients, $sent );

		$this->assertSame( array( $ok, false, $ok ), array( $outcome['sent'], $outcome['queued'], null === $outcome['error'] ) );
	}

	/**
	 * @return array<string, array{0: bool, 1: bool, 2: bool}>
	 */
	public static function provide_tests(): array {
		return array(
			'mailed'        => array( true, true, true ),
			'refused'       => array( true, false, false ),
			'no recipients' => array( false, false, false ),
		);
	}
}
