<?php
/**
 * Tests for the administrator baseline diff.
 *
 * This is the detection core of the new-administrator alert: everything the
 * hooks miss (direct database inserts, code bypassing the WordPress user API,
 * accounts added while the plugin was inactive) is found here and nowhere else.
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
final class BaselineIdDiffTest extends TestCase {

	public function test_reports_an_administrator_that_is_not_in_the_baseline(): void {
		$this->assertSame( [ 7 ], BaselineDiff::ids( [ 1, 3 ], [ 1, 3, 7 ] ) );
	}

	public function test_reports_nothing_when_the_admin_set_is_unchanged(): void {
		$this->assertSame( [], BaselineDiff::ids( [ 1, 3 ], [ 3, 1 ] ) );
	}

	public function test_reports_every_new_administrator_of_a_batch(): void {
		$this->assertSame( [ 5, 9 ], BaselineDiff::ids( [ 1 ], [ 1, 5, 9 ] ) );
	}

	public function test_a_removed_administrator_is_not_reported_as_new(): void {
		$this->assertSame( [], BaselineDiff::ids( [ 1, 3, 7 ], [ 1 ] ) );
	}

	public function test_a_demoted_administrator_alerts_again_when_re_promoted(): void {
		// The baseline is replaced on every scan, so ID 3 leaves it when
		// demoted and is genuinely new again on the way back up.
		$after_demotion = BaselineDiff::ids( [ 1, 3 ], [ 1 ] );
		$after_re_promo = BaselineDiff::ids( [ 1 ], [ 1, 3 ] );

		$this->assertSame( [], $after_demotion );
		$this->assertSame( [ 3 ], $after_re_promo );
	}

	public function test_an_empty_baseline_reports_every_current_administrator(): void {
		$this->assertSame( [ 1, 2 ], BaselineDiff::ids( [], [ 2, 1 ] ) );
	}

	/**
	 * IDs arrive from get_users() and from a stored option that may have been
	 * written by an older version, so string and duplicate values must not
	 * produce phantom "new administrator" reports.
	 */
	public function test_normalizes_mixed_types_before_comparing(): void {
		$this->assertSame( [], BaselineDiff::ids( [ '1', 3, 3 ], [ 1, '3' ] ) );
	}

	public function test_drops_zero_and_negative_ids(): void {
		$this->assertSame( [ 4 ], BaselineDiff::ids( [ 0, 1 ], [ 1, 0, -2, 4 ] ) );
	}
}
