<?php
/**
 * Tests for ban subjects: IPv6 addresses are banned per /64.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\AutoBanner;
use LightweightPlugins\Firewall\Rules\BanList;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;

/**
 * @covers \LightweightPlugins\Firewall\Rules\AutoBanner
 */
final class AutoBannerTest extends MonkeyTestCase {

	private ArrayStorage $storage;

	private OptionStore $options;

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		$this->options = OptionStore::install( [ 'lw_firewall' => [ 'auto_ban_threshold' => 3 ] ] );
		$this->storage = new ArrayStorage();
	}

	public function test_a_ban_covers_every_address_in_the_slash_64(): void {
		( new AutoBanner( $this->storage ) )->ban( '2001:db8:1:1::1', 600, 'login_lockout' );

		$this->assertTrue( ( new AutoBanner( $this->storage ) )->is_banned( '2001:db8:1:1:ffff:ffff:ffff:fffe' ) );
	}

	public function test_a_ban_does_not_spill_into_the_next_slash_64(): void {
		( new AutoBanner( $this->storage ) )->ban( '2001:db8:1:1::1', 600 );

		$this->assertFalse( ( new AutoBanner( $this->storage ) )->is_banned( '2001:db8:1:2::1' ) );
	}

	public function test_an_ipv4_ban_stays_per_address(): void {
		( new AutoBanner( $this->storage ) )->ban( '203.0.113.7', 600 );

		$this->assertFalse( ( new AutoBanner( $this->storage ) )->is_banned( '203.0.113.8' ) );
	}

	/**
	 * The attack: rotate the interface identifier on every request. Each
	 * address used to get its own violation counter and never reached the
	 * threshold.
	 */
	public function test_violations_from_rotating_addresses_in_one_slash_64_add_up(): void {
		$banner = new AutoBanner( $this->storage );

		foreach ( [ '2001:db8:1:1::a', '2001:db8:1:1::b', '2001:db8:1:1::c' ] as $ip ) {
			$banner->record_violation( $ip );
		}

		$this->assertTrue( $banner->is_banned( '2001:db8:1:1::d' ) );
	}

	public function test_the_ban_index_lists_the_slash_64(): void {
		( new AutoBanner( $this->storage ) )->ban( '2001:db8:1:1::1', 600 );

		$this->assertSame( [ '2001:db8:1:1::/64' ], array_column( BanList::all(), 'ip' ) );
	}

	/**
	 * @dataProvider provide_unban_targets
	 *
	 * @param string $target What the operator passes to unban.
	 */
	public function test_unbanning_any_address_in_the_slash_64_lifts_the_ban( string $target ): void {
		$banner = new AutoBanner( $this->storage );
		$banner->ban( '2001:db8:1:1::1', 600 );

		$banner->unban( $target );

		$this->assertFalse( $banner->is_banned( '2001:db8:1:1::1' ) );
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function provide_unban_targets(): array {
		return [
			'the banned address'        => [ '2001:db8:1:1::1' ],
			'another address in the 64' => [ '2001:db8:1:1::beef' ],
			'the /64 key'               => [ '2001:db8:1:1::/64' ],
		];
	}

	public function test_unban_clears_the_shared_counters(): void {
		$banner = new AutoBanner( $this->storage );
		$banner->record_violation( '2001:db8:1:1::a' );
		$banner->record_violation( '2001:db8:1:1::b' );

		$banner->unban( '2001:db8:1:1::c' );
		$banner->record_violation( '2001:db8:1:1::d' );

		$this->assertFalse( $banner->is_banned( '2001:db8:1:1::d' ) );
	}

	/**
	 * 1.5.8 wrote per-address keys. They stay enforced until they expire, and
	 * the operator can still lift them — from the address or from the /64.
	 *
	 * @dataProvider provide_unban_targets
	 *
	 * @param string $target What the operator passes to unban.
	 */
	public function test_a_legacy_per_address_ban_can_still_be_lifted( string $target ): void {
		$this->storage->set( 'ban_2001:db8:1:1::1', 1, 600 );
		BanList::record( '2001:db8:1:1::1', 600, 'login_lockout' );
		$banner = new AutoBanner( $this->storage );

		$banner->unban( $target );

		$this->assertFalse( $banner->is_banned( '2001:db8:1:1::1' ) );
		$this->assertSame( [], BanList::all() );
	}

	public function test_a_legacy_per_address_ban_is_still_enforced(): void {
		$this->storage->set( 'ban_2001:db8:1:1::1', 1, 600 );

		$this->assertTrue( ( new AutoBanner( $this->storage ) )->is_banned( '2001:db8:1:1::1' ) );
	}

	public function test_unban_rejects_an_invalid_target(): void {
		$this->assertFalse( ( new AutoBanner( $this->storage ) )->unban( 'nonsense' ) );
	}
}
