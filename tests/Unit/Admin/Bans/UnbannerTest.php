<?php
/**
 * Tests for per-address unban results.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Admin\Bans;

use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Admin\Bans\Unbanner;
use LightweightPlugins\Firewall\Rules\AutoBanner;
use LightweightPlugins\Firewall\Rules\BanList;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\ArrayStorage;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\Tests\Unit\Support\StickyStorage;

/**
 * @covers \LightweightPlugins\Firewall\Admin\Bans\Unbanner
 */
final class UnbannerTest extends MonkeyTestCase {

	private ArrayStorage $storage;

	protected function setUp(): void {
		parent::setUp();

		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		Functions\stubTranslationFunctions();
		OptionStore::install( array( 'lw_firewall' => array() ) );
		$this->storage = new ArrayStorage();
	}

	public function test_reports_each_address_separately(): void {
		$banner = new AutoBanner( $this->storage );
		$banner->ban( '203.0.113.7', 600, 'login_lockout' );

		$results = ( new Unbanner( $banner ) )->lift( array( '203.0.113.7', 'not-an-ip' ) );

		$this->assertSame( array( true, false ), array_column( $results, 'ok' ) );
	}

	/**
	 * Regression: "Unblock every banned address" always reported success and
	 * wiped the index even when the storage refused a delete.
	 */
	public function test_a_refused_delete_is_reported_and_stays_listed(): void {
		$banner = new AutoBanner( new StickyStorage() );
		$banner->ban( '203.0.113.7', 600, 'login_lockout' );

		$results = ( new Unbanner( $banner ) )->lift_all();

		$this->assertSame( array( false, array( '203.0.113.7' ) ), array( $results[0]['ok'], BanList::ips() ) );
	}

	public function test_lift_all_clears_every_tracked_ban(): void {
		$banner = new AutoBanner( $this->storage );
		$banner->ban( '203.0.113.7', 600 );
		$banner->ban( '203.0.113.8', 600 );

		( new Unbanner( $banner ) )->lift_all();

		$this->assertSame( array(), BanList::ips() );
	}

	public function test_an_address_that_was_not_banned_is_reported_as_such(): void {
		$result = ( new Unbanner( new AutoBanner( $this->storage ) ) )->lift( array( '203.0.113.9' ) )[0];

		$this->assertSame( array( true, 'This address was not banned. Its counters were cleared anyway.' ), array( $result['ok'], $result['message'] ) );
	}
}
