<?php
/**
 * Tests for the ban index pruning rule.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\BanList;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\BanList
 */
final class BanListTest extends TestCase {

	private const NOW = 1700000000;

	/**
	 * One index entry.
	 *
	 * @param int    $expires Expiry timestamp.
	 * @param string $reason  Reason code.
	 * @param int    $time    When the ban started.
	 * @return array<string, mixed>
	 */
	private static function entry( int $expires, string $reason = 'login_lockout', int $time = self::NOW ): array {
		return [
			'expires' => $expires,
			'reason'  => $reason,
			'time'    => $time,
		];
	}

	public function test_keeps_a_ban_that_has_not_expired(): void {
		$kept = BanList::prune( [ '1.2.3.4' => self::entry( self::NOW + 60 ) ], self::NOW );

		$this->assertSame( [ '1.2.3.4' ], array_keys( $kept ) );
		$this->assertSame( 'login_lockout', $kept['1.2.3.4']['reason'] );
	}

	public function test_drops_a_ban_that_has_expired(): void {
		$this->assertSame( [], BanList::prune( [ '1.2.3.4' => self::entry( self::NOW - 1 ) ], self::NOW ) );
	}

	/**
	 * A ban expiring exactly now is over — keeping it would show a block the
	 * storage backend has already stopped enforcing.
	 */
	public function test_drops_a_ban_expiring_exactly_now(): void {
		$this->assertSame( [], BanList::prune( [ '1.2.3.4' => self::entry( self::NOW ) ], self::NOW ) );
	}

	public function test_keeps_only_the_live_entries_of_a_mixed_index(): void {
		$kept = BanList::prune(
			[
				'1.1.1.1' => self::entry( self::NOW - 10 ),
				'2.2.2.2' => self::entry( self::NOW + 10 ),
				'3.3.3.3' => self::entry( self::NOW - 3600 ),
				'4.4.4.4' => self::entry( self::NOW + 3600 ),
			],
			self::NOW
		);

		$this->assertSame( [ '2.2.2.2', '4.4.4.4' ], array_keys( $kept ) );
	}

	/**
	 * The option can hold anything a previous version wrote, so a malformed
	 * entry must be dropped rather than crash the settings screen.
	 */
	public function test_drops_malformed_entries(): void {
		$kept = BanList::prune(
			[
				'1.1.1.1' => 'not an array',
				'2.2.2.2' => [ 'reason' => 'login_lockout' ],
				'3.3.3.3' => self::entry( self::NOW + 60 ),
			],
			self::NOW
		);

		$this->assertSame( [ '3.3.3.3' ], array_keys( $kept ) );
	}

	public function test_fills_in_missing_reason_and_time(): void {
		$kept = BanList::prune( [ '1.2.3.4' => [ 'expires' => self::NOW + 60 ] ], self::NOW );

		$this->assertSame( '', $kept['1.2.3.4']['reason'] );
		$this->assertSame( 0, $kept['1.2.3.4']['time'] );
	}

	/**
	 * A distributed attack must not be able to grow the option without bound.
	 * When the cap is hit the newest bans are the ones worth keeping — those
	 * are the ones an administrator is about to be asked to lift.
	 */
	public function test_caps_the_index_and_keeps_the_newest_bans(): void {
		$entries = [];

		for ( $i = 1; $i <= 520; $i++ ) {
			$entries[ '10.0.' . intdiv( $i, 256 ) . '.' . ( $i % 256 ) ] = self::entry( self::NOW + 3600, 'rate_limit', self::NOW + $i );
		}

		$kept = BanList::prune( $entries, self::NOW );

		$this->assertCount( 500, $kept );
		$this->assertSame( self::NOW + 520, reset( $kept )['time'] );
		$this->assertSame( self::NOW + 21, end( $kept )['time'] );
	}

	public function test_an_empty_index_stays_empty(): void {
		$this->assertSame( [], BanList::prune( [], self::NOW ) );
	}
}
