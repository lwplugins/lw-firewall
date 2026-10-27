<?php
/**
 * Tests for the database-backed attempt counters.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\FakeWpdb;
use LightweightPlugins\Firewall\TwoFactor\AttemptCounter;
use LightweightPlugins\Firewall\TwoFactor\FailureThrottle;
use LightweightPlugins\Firewall\TwoFactor\PendingLogin;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;

require_once dirname( __DIR__ ) . '/Support/FakeWpdb.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\AttemptCounter
 * @covers \LightweightPlugins\Firewall\TwoFactor\FailureThrottle
 */
#[RequiresPhpExtension( 'pdo_sqlite' )]
final class AttemptCounterTest extends MonkeyTestCase {

	private int $now = 1700000000;

	private FakeWpdb $db;

	private int $flushes = 0;

	protected function setUp(): void {
		parent::setUp();
		$this->db = new FakeWpdb();
		Functions\when( 'wp_cache_delete' )->alias(
			function ( $id, $group ) {
				$this->assertSame( 'user_meta', $group );
				++$this->flushes;
				return true;
			}
		);
	}

	private function counter(): AttemptCounter {
		return new AttemptCounter( fn (): int => $this->now, $this->db );
	}

	public function test_increments_count_up_inside_the_window(): void {
		$c = $this->counter();

		$this->assertSame( 0, $c->count( 5, 'k', 300 ) );
		$this->assertSame( 1, $c->increment( 5, 'k', 300 ) );
		$this->assertSame( 2, $c->increment( 5, 'k', 300 ) );
		$this->assertSame( 2, $c->count( 5, 'k', 300 ) );
		$this->assertSame( 0, $c->count( 6, 'k', 300 ), 'Per account.' );
		$this->assertGreaterThan( 0, $this->flushes, 'The meta cache is flushed after writes.' );
	}

	public function test_the_window_expires_and_restarts(): void {
		$c = $this->counter();
		$c->increment( 5, 'k', 300 );
		$c->increment( 5, 'k', 300 );

		$this->now += 301;
		$this->assertSame( 0, $c->count( 5, 'k', 300 ) );
		$this->assertSame( 1, $c->increment( 5, 'k', 300 ) );
	}

	public function test_a_database_error_reads_as_exhausted(): void {
		$c = $this->counter();
		$c->increment( 5, 'k', 300 );

		$this->db->fail = true;
		$this->assertSame( AttemptCounter::EXHAUSTED, $c->increment( 5, 'k', 300 ) );
		$this->assertSame( AttemptCounter::EXHAUSTED, $c->count( 5, 'k', 300 ) );
	}

	public function test_duplicate_rows_are_counted_together(): void {
		$c = $this->counter();
		$c->increment( 5, 'k', 300 );
		$this->db->query( "INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (5, 'k', '" . ( $this->now * 1000 ) . "')" );

		$this->assertSame( 2, $c->increment( 5, 'k', 300 ) );
	}

	public function test_purge_removes_only_expired_rows_of_the_prefix(): void {
		$c = $this->counter();
		$c->increment( 5, 'pre_old', 300 );
		$this->now += 400;
		$c->increment( 5, 'pre_new', 300 );
		$c->increment( 5, 'other', 1 );
		$this->now += 10;

		$c->purge( 5, 'pre_', 300 );

		$this->assertSame( array( 'pre_new', 'other' ), array_column( $this->db->rows(), 'meta_key' ) );
	}

	public function test_hold_starts_a_window_with_a_count(): void {
		$c = $this->counter();
		$c->increment( 5, 'k', 900 );
		$this->assertTrue( $c->hold( 5, 'k', 10 ) );

		$this->assertSame( 10, $c->count( 5, 'k', 900 ) );
		$this->assertCount( 1, $this->db->rows() );
	}

	// ---- throttle on the counter --------------------------------------------

	private function throttle(): FailureThrottle {
		return new FailureThrottle( $this->counter() );
	}

	public function test_the_eleventh_failure_is_blocked_and_the_block_expires(): void {
		$t = $this->throttle();
		for ( $i = 1; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->assertFalse( ( $t->claim( 5 ) && $t->record_failure( 5 ) ) );
			$this->assertFalse( $t->is_blocked( 5 ) );
		}
		$this->assertTrue( ( $t->claim( 5 ) && $t->record_failure( 5 ) ), 'Tenth failure blocks.' );
		$this->assertTrue( $t->is_blocked( 5 ), 'An eleventh attempt is blocked.' );
		$this->assertFalse( $t->is_blocked( 6 ) );

		$this->now += FailureThrottle::BLOCK - 1;
		$this->assertTrue( $t->is_blocked( 5 ) );
		$this->now += 2;
		$this->assertFalse( $t->is_blocked( 5 ), 'Window expiry resets.' );
		$this->assertFalse( ( $t->claim( 5 ) && $t->record_failure( 5 ) ) );
	}

	public function test_old_failures_age_out(): void {
		$t = $this->throttle();
		for ( $i = 1; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$t->claim( 5 );
			$t->record_failure( 5 );
		}
		$this->now += FailureThrottle::WINDOW + 1;

		$this->assertFalse( ( $t->claim( 5 ) && $t->record_failure( 5 ) ) );
		$this->assertFalse( $t->is_blocked( 5 ) );
	}

	public function test_a_database_failure_blocks(): void {
		$this->db->fail = true;

		$this->assertTrue( $this->throttle()->is_blocked( 5 ) );
		$this->assertTrue( $this->throttle()->record_failure( 5 ) );
	}

	public function test_no_request_storage_dependency_is_left(): void {
		foreach ( array( FailureThrottle::class, PendingLogin::class ) as $class ) {
			$ctor = ( new \ReflectionClass( $class ) )->getConstructor();
			foreach ( $ctor ? $ctor->getParameters() : array() as $param ) {
				$this->assertStringNotContainsString( 'StorageInterface', (string) $param->getType(), $class . ' must not count on the fail-open request storage.' );
			}
		}
	}

	// ---- fix round 3 --------------------------------------------------------

	public function test_hold_is_one_update_that_keeps_the_row(): void {
		$c = $this->counter();
		$c->increment( 5, 'k', 900 );
		$c->increment( 5, 'k', 900 );

		$this->assertTrue( $c->hold( 5, 'k', 10 ) );
		$this->assertSame( 10, $c->count( 5, 'k', 900 ) );
		$this->assertCount( 1, $this->db->rows() );

		$this->assertTrue( $c->hold( 6, 'k', 3 ), 'A missing row is created first.' );
		$this->assertSame( 3, $c->count( 6, 'k', 900 ) );
	}

	public function test_a_failing_hold_leaves_the_old_count(): void {
		$c = $this->counter();
		$c->increment( 5, 'k', 900 );
		$this->db->fail_matching = "/SET meta_value = '/";

		$this->assertFalse( $c->hold( 5, 'k', 10 ) );
		$this->assertSame( 1, $c->count( 5, 'k', 900 ), 'Nothing was deleted.' );
	}

	public function test_claims_share_one_budget_across_parallel_attempts(): void {
		$t = $this->throttle();

		// Twelve answers in flight at once (e.g. over three pending tokens), none recorded yet.
		$claimed = 0;
		for ( $i = 0; $i < 12; $i++ ) {
			$claimed += $t->claim( 5 ) ? 1 : 0;
		}

		$this->assertSame( FailureThrottle::MAX_FAILURES, $claimed, 'At most ten answers get checked per window.' );
		$this->assertTrue( $t->is_blocked( 5 ) );
	}

	public function test_a_failing_block_write_still_reads_as_blocked(): void {
		$t = $this->throttle();
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$t->claim( 5 );
		}
		$this->db->fail_matching = "/SET meta_value = '/";

		$this->assertFalse( $t->claim( 5 ) );
		$this->assertTrue( $t->record_failure( 5 ) );
		$this->assertTrue( $t->is_blocked( 5 ) );
	}

	public function test_success_gives_the_budget_back(): void {
		$t = $this->throttle();
		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES - 1; $i++ ) {
			$t->claim( 5 );
		}
		$t->succeeded( 5 );

		for ( $i = 0; $i < FailureThrottle::MAX_FAILURES; $i++ ) {
			$this->assertTrue( $t->claim( 5 ) );
		}
	}

	public function test_a_database_failure_refuses_the_claim(): void {
		$this->db->fail = true;

		$this->assertFalse( $this->throttle()->claim( 5 ) );
	}
}
