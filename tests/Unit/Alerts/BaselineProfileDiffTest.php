<?php
/**
 * Tests for the administrator identity diff.
 *
 * This is what catches an account takeover: an attacker who rewrites an
 * existing administrator's email address owns the password reset flow, and the
 * user ID never changes — so the ID diff in AdminBaselineTest would see
 * nothing at all.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Alerts;

use LightweightPlugins\Firewall\Alerts\BaselineDiff;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Alerts\BaselineDiff
 */
final class BaselineProfileDiffTest extends TestCase {

	/**
	 * A complete fingerprint for one administrator.
	 *
	 * @param string $login Username.
	 * @param string $email Email address.
	 * @param string $pass  Password-hash digest.
	 * @return array<string, string>
	 */
	private static function profile( string $login = 'admin', string $email = 'admin@example.test', string $pass = 'digest-a' ): array {
		return [
			'login' => $login,
			'email' => $email,
			'pass'  => $pass,
		];
	}

	public function test_reports_nothing_when_the_account_is_untouched(): void {
		$snapshot = [ 5 => self::profile() ];

		$this->assertSame( [], BaselineDiff::profiles( $snapshot, $snapshot ) );
	}

	public function test_reports_an_email_address_takeover(): void {
		$changes = BaselineDiff::profiles(
			[ 5 => self::profile( 'admin', 'owner@example.test' ) ],
			[ 5 => self::profile( 'admin', 'attacker@evil.test' ) ]
		);

		$this->assertSame(
			[
				[
					'id'    => 5,
					'field' => 'email',
					'from'  => 'owner@example.test',
					'to'    => 'attacker@evil.test',
				],
			],
			$changes
		);
	}

	public function test_reports_a_username_change(): void {
		$changes = BaselineDiff::profiles(
			[ 5 => self::profile( 'owner' ) ],
			[ 5 => self::profile( 'r00t' ) ]
		);

		$this->assertCount( 1, $changes );
		$this->assertSame( 'login', $changes[0]['field'] );
		$this->assertSame( 'owner', $changes[0]['from'] );
		$this->assertSame( 'r00t', $changes[0]['to'] );
	}

	public function test_reports_a_password_change(): void {
		$changes = BaselineDiff::profiles(
			[ 5 => self::profile( 'admin', 'admin@example.test', 'digest-a' ) ],
			[ 5 => self::profile( 'admin', 'admin@example.test', 'digest-b' ) ]
		);

		$this->assertCount( 1, $changes );
		$this->assertSame( 'pass', $changes[0]['field'] );
	}

	public function test_reports_every_field_that_changed_at_once(): void {
		$changes = BaselineDiff::profiles(
			[ 5 => self::profile( 'owner', 'owner@example.test', 'digest-a' ) ],
			[ 5 => self::profile( 'r00t', 'attacker@evil.test', 'digest-b' ) ]
		);

		$this->assertSame( [ 'login', 'email', 'pass' ], array_column( $changes, 'field' ) );
	}

	/**
	 * A brand-new administrator is already reported by the ID diff; reporting
	 * it here too would send two emails for one event.
	 */
	public function test_ignores_an_account_the_baseline_never_had(): void {
		$changes = BaselineDiff::profiles(
			[ 5 => self::profile() ],
			[
				5 => self::profile(),
				9 => self::profile( 'newadmin', 'new@example.test', 'digest-z' ),
			]
		);

		$this->assertSame( [], $changes );
	}

	public function test_ignores_an_account_that_disappeared(): void {
		$changes = BaselineDiff::profiles(
			[
				5 => self::profile(),
				9 => self::profile( 'gone', 'gone@example.test', 'digest-z' ),
			],
			[ 5 => self::profile() ]
		);

		$this->assertSame( [], $changes );
	}

	/**
	 * Snapshots written before identity tracking existed hold only IDs. Those
	 * entries must be filled in silently, not reported as changes.
	 */
	public function test_ignores_fields_missing_from_the_stored_snapshot(): void {
		$changes = BaselineDiff::profiles(
			[ 5 => [] ],
			[ 5 => self::profile() ]
		);

		$this->assertSame( [], $changes );
	}

	public function test_reports_changes_on_several_administrators(): void {
		$changes = BaselineDiff::profiles(
			[
				5 => self::profile( 'a', 'a@example.test' ),
				7 => self::profile( 'b', 'b@example.test' ),
			],
			[
				5 => self::profile( 'a', 'hacked@evil.test' ),
				7 => self::profile( 'b', 'b@example.test', 'digest-new' ),
			]
		);

		$this->assertSame( [ 5, 7 ], array_column( $changes, 'id' ) );
		$this->assertSame( [ 'email', 'pass' ], array_column( $changes, 'field' ) );
	}

	/**
	 * Option values come back from the database with array keys as strings.
	 */
	/**
	 * Regression: a snapshot written before identity tracking existed holds IDs
	 * but no fingerprints. Writing one account back must keep the others in the
	 * snapshot — otherwise the next scan reports every remaining administrator
	 * as brand new and mails a false compromise alert.
	 */
	public function test_keeps_known_ids_that_have_no_fingerprint_yet(): void {
		$merged = BaselineDiff::with_known_ids( [ 5 => self::profile() ], [ 1, 2, 5 ] );

		$this->assertSame( [ 1, 2, 5 ], array_keys( $merged ) );
		$this->assertSame( [], $merged[1] );
		$this->assertSame( self::profile(), $merged[5] );
	}

	public function test_a_filled_in_placeholder_does_not_raise_an_alert(): void {
		$legacy  = BaselineDiff::with_known_ids( [], [ 5 ] );
		$changes = BaselineDiff::profiles( $legacy, [ 5 => self::profile() ] );

		$this->assertSame( [], $changes );
	}

	public function test_a_takeover_is_still_caught_after_the_placeholder_is_filled(): void {
		$filled  = BaselineDiff::with_known_ids( [ 5 => self::profile() ], [ 5 ] );
		$changes = BaselineDiff::profiles( $filled, [ 5 => self::profile( 'admin', 'attacker@evil.test' ) ] );

		$this->assertCount( 1, $changes );
		$this->assertSame( 'email', $changes[0]['field'] );
	}

	public function test_normalizes_string_user_ids_before_comparing(): void {
		$changes = BaselineDiff::profiles(
			[ '5' => self::profile() ],
			[ 5 => self::profile() ]
		);

		$this->assertSame( [], $changes );
	}
}
