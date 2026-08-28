<?php
/**
 * Tests for password-reset rate limiting.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\ResetLimiter;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\ResetLimiter
 */
final class ResetLimiterTest extends TestCase {

	/**
	 * Limits with every axis generous enough not to interfere, so a test can
	 * tighten just the one it is about.
	 *
	 * @param array<string, int> $overrides Limits to tighten.
	 * @return array<string, int>
	 */
	private static function limits( array $overrides = [] ): array {
		return array_merge(
			[
				'ip_max'        => 1000,
				'ip_window'     => 900,
				'user_max'      => 1000,
				'user_window'   => 3600,
				'global_max'    => 1000,
				'global_window' => 3600,
			],
			$overrides
		);
	}

	public function test_allows_requests_up_to_the_per_ip_limit(): void {
		$limiter = new ResetLimiter( new ArrayStorage(), self::limits( [ 'ip_max' => 3 ] ) );

		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '1.2.3.4', 7 ) );
		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '1.2.3.4', 7 ) );
		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '1.2.3.4', 7 ) );
	}

	public function test_blocks_the_request_after_the_per_ip_limit(): void {
		$limiter = new ResetLimiter( new ArrayStorage(), self::limits( [ 'ip_max' => 2 ] ) );

		$limiter->record( '1.2.3.4', 7 );
		$limiter->record( '1.2.3.4', 7 );

		$this->assertSame( ResetLimiter::IP, $limiter->record( '1.2.3.4', 7 ) );
	}

	public function test_the_per_ip_limit_is_per_address(): void {
		$limiter = new ResetLimiter( new ArrayStorage(), self::limits( [ 'ip_max' => 1 ] ) );

		$limiter->record( '1.2.3.4', 7 );

		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '5.6.7.8', 7 ) );
	}

	/**
	 * The point of the per-account axis: a flood spread across many IPs is
	 * invisible to per-IP limiting, and that is exactly how someone floods a
	 * specific person's inbox.
	 */
	public function test_blocks_a_distributed_flood_of_one_account(): void {
		$limiter = new ResetLimiter( new ArrayStorage(), self::limits( [ 'ip_max' => 100, 'user_max' => 3 ] ) );

		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '1.1.1.1', 7 ) );
		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '2.2.2.2', 7 ) );
		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '3.3.3.3', 7 ) );
		$this->assertSame( ResetLimiter::USER, $limiter->record( '4.4.4.4', 7 ) );
	}

	public function test_the_per_account_limit_is_per_account(): void {
		$limiter = new ResetLimiter( new ArrayStorage(), self::limits( [ 'user_max' => 1 ] ) );

		$limiter->record( '1.1.1.1', 7 );

		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '2.2.2.2', 8 ) );
	}

	public function test_blocks_once_the_site_wide_cap_is_reached(): void {
		$limiter = new ResetLimiter( new ArrayStorage(), self::limits( [ 'global_max' => 2 ] ) );

		$limiter->record( '1.1.1.1', 7 );
		$limiter->record( '2.2.2.2', 8 );

		$this->assertSame( ResetLimiter::GLOBAL, $limiter->record( '3.3.3.3', 9 ) );
	}

	/**
	 * An unknown account (the submitted name matched nobody) still burns the
	 * IP and site-wide counters — that is what makes the limiter useful against
	 * username probing.
	 */
	public function test_an_unknown_account_still_counts_against_the_ip(): void {
		$limiter = new ResetLimiter( new ArrayStorage(), self::limits( [ 'ip_max' => 2 ] ) );

		$limiter->record( '1.2.3.4', 0 );
		$limiter->record( '1.2.3.4', 0 );

		$this->assertSame( ResetLimiter::IP, $limiter->record( '1.2.3.4', 0 ) );
	}

	/**
	 * Once the IP is over its own limit the request is refused without touching
	 * the target counter, so an attacker cannot use their own flood to lock the
	 * victim out of a genuine reset.
	 */
	public function test_an_ip_block_does_not_burn_the_targets_allowance(): void {
		$storage = new ArrayStorage();
		$limiter = new ResetLimiter( $storage, self::limits( [ 'ip_max' => 1, 'user_max' => 2 ] ) );

		$limiter->record( '9.9.9.9', 7 );
		$limiter->record( '9.9.9.9', 7 );
		$limiter->record( '9.9.9.9', 7 );

		// The victim asks from their own address and is still within budget.
		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '1.1.1.1', 7 ) );
	}

	/**
	 * Regression: the site-wide counter used to be charged before the per-account
	 * check, so refused requests drained the hourly email budget. A flood against
	 * one account could exhaust it and deny password resets to everyone else.
	 */
	public function test_a_refused_account_request_does_not_drain_the_email_budget(): void {
		$storage = new ArrayStorage();
		$limiter = new ResetLimiter( $storage, self::limits( array( 'ip_max' => 100, 'user_max' => 1, 'global_max' => 3 ) ) );

		$limiter->record( '1.1.1.1', 7 );

		// Five more requests for the same account, all refused on the account
		// limit — none of them is an email, so none may cost the budget.
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertSame( ResetLimiter::USER, $limiter->record( '2.2.2.2', 7 ) );
		}

		// A different account still has budget left.
		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '3.3.3.3', 8 ) );
		$this->assertSame( 2, $storage->get( 'reset_all' ) );
	}

	/**
	 * Bot traffic counts against the sender so a flood still gets banned, but it
	 * must not touch the target's allowance or the email budget.
	 */
	public function test_a_rejected_bot_request_only_costs_the_sender(): void {
		$storage = new ArrayStorage();
		$limiter = new ResetLimiter( $storage, self::limits( array( 'ip_max' => 2 ) ) );

		$limiter->record_rejected( '9.9.9.9' );
		$limiter->record_rejected( '9.9.9.9' );

		$this->assertSame( 2, $storage->get( 'reset_ip_9.9.9.9' ) );
		$this->assertNull( $storage->get( 'reset_all' ) );
		$this->assertNull( $storage->get( 'reset_user_7' ) );
	}

	/**
	 * @dataProvider provide_disabled_axes
	 *
	 * @param string $axis Limit key set to zero.
	 */
	public function test_a_zero_limit_disables_that_axis( string $axis ): void {
		$limiter = new ResetLimiter( new ArrayStorage(), self::limits( [ $axis => 0 ] ) );

		$verdict = ResetLimiter::ALLOW;

		for ( $i = 0; $i < 50; $i++ ) {
			$verdict = $limiter->record( '1.2.3.4', 7 );
		}

		$this->assertSame( ResetLimiter::ALLOW, $verdict );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_disabled_axes(): array {
		return [
			'per IP'    => [ 'ip_max' ],
			'per user'  => [ 'user_max' ],
			'site-wide' => [ 'global_max' ],
		];
	}

	public function test_an_empty_ip_skips_the_per_ip_axis(): void {
		$limiter = new ResetLimiter( new ArrayStorage(), self::limits( [ 'ip_max' => 1 ] ) );

		$limiter->record( '', 7 );

		$this->assertSame( ResetLimiter::ALLOW, $limiter->record( '', 7 ) );
	}
}
