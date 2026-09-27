<?php
/**
 * Tests for the filter_params retirement.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Upgrade;

use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\Upgrade\FilterParamsMigration;

/**
 * @covers \LightweightPlugins\Firewall\Upgrade\FilterParamsMigration
 */
final class FilterParamsMigrationTest extends MonkeyTestCase {

	public function test_removes_the_retired_key(): void {
		$store = OptionStore::install( [ 'lw_firewall' => [ 'enabled' => true, 'filter_params' => [ 'filter_|30' ] ] ] );

		FilterParamsMigration::maybe_apply();

		$this->assertSame( [ 'enabled' => true ], $store->data['lw_firewall'] );
	}

	public function test_records_entries_without_a_replacement(): void {
		$store = OptionStore::install( [ 'lw_firewall' => [ 'filter_params' => [ 'filter_|30', 'query_type_|30', 'add-to-cart|10' ] ] ] );

		FilterParamsMigration::maybe_apply();

		$this->assertSame( [ 'add-to-cart|10' ], $store->data[ FilterParamsMigration::DROPPED_OPTION ] );
	}

	public function test_records_nothing_when_every_entry_is_covered(): void {
		$store = OptionStore::install( [ 'lw_firewall' => [ 'filter_params' => [ 'filter_|30', 'query_type_|30' ] ] ] );

		FilterParamsMigration::maybe_apply();

		$this->assertArrayNotHasKey( FilterParamsMigration::DROPPED_OPTION, $store->data );
	}

	public function test_leaves_settings_without_the_key_untouched(): void {
		$store = OptionStore::install( [ 'lw_firewall' => [ 'enabled' => false ] ] );

		FilterParamsMigration::maybe_apply();

		$this->assertSame( [ 'lw_firewall' => [ 'enabled' => false ] ], $store->data );
	}

	public function test_accepts_a_legacy_string_list(): void {
		$this->assertSame( [ 'add-to-cart|10' ], FilterParamsMigration::uncovered( "filter_|30\nadd-to-cart|10" ) );
	}
}
