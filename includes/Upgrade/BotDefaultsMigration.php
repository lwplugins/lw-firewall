<?php
/**
 * One-time refresh of the shipped blocked-bot list.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Upgrade;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Replaces the stored bot list with the current defaults, but only on sites
 * that never edited it.
 *
 * Activation writes the whole default set into the database, so a plain
 * defaults change would never reach an existing install: the stored value
 * always wins over get_defaults(). Shipping a narrower list without this
 * migration would mean every site already running the plugin keeps blocking
 * the AI agents that send referral traffic.
 *
 * The safety rail is exact equality with the list shipped up to 1.5.7. Anyone
 * who added, removed or reordered a single entry has expressed an intent, and
 * their list is left untouched.
 */
final class BotDefaultsMigration {

	/**
	 * Option holding the highest migration revision already applied.
	 */
	public const REVISION_OPTION = 'lw_firewall_bot_defaults_rev';

	/**
	 * Current revision. Bump only when shipping another default-list change
	 * that should reach untouched installs.
	 */
	private const REVISION = 1;

	/**
	 * The blocked_bots default as shipped from 1.0.0 through 1.5.7.
	 *
	 * @var array<int, string>
	 */
	private const LEGACY_DEFAULT = [
		'meta-externalagent',
		'meta-externalfetcher',
		'gptbot',
		'chatgpt-user',
		'claudebot',
		'claude-web',
		'bytespider',
		'amazonbot',
		'anthropic-ai',
		'cohere-ai',
		'diffbot',
		'perplexitybot',
		'youbot',
		'petalbot',
		'semrushbot',
		'ahrefsbot',
		'dotbot',
		'mj12bot',
		'barkrowler',
		'dataforseobot',
	];

	/**
	 * Run the migration at most once per site.
	 *
	 * @return void
	 */
	public static function maybe_apply(): void {
		if ( (int) get_option( self::REVISION_OPTION, 0 ) >= self::REVISION ) {
			return;
		}

		// Stamp before rewriting: a half-finished run must not retry on every
		// request and fight an operator who edits the list in the meantime.
		update_option( self::REVISION_OPTION, self::REVISION, true );

		self::refresh_untouched_list();
	}

	/**
	 * Overwrite the stored list when it still matches the legacy default.
	 *
	 * @return void
	 */
	private static function refresh_untouched_list(): void {
		$saved = get_option( Options::OPTION_NAME, [] );

		// No stored settings at all: get_defaults() already applies.
		if ( ! is_array( $saved ) || ! array_key_exists( 'blocked_bots', $saved ) ) {
			return;
		}

		if ( ! self::is_legacy_default( $saved['blocked_bots'] ) ) {
			return;
		}

		$defaults              = Options::get_defaults();
		$saved['blocked_bots'] = $defaults['blocked_bots'];

		update_option( Options::OPTION_NAME, $saved );
	}

	/**
	 * Is this stored value byte-for-byte the list we used to ship?
	 *
	 * Compared as a sorted, lower-cased set so a textarea round-trip (which
	 * can reorder or re-case entries without changing what is blocked) still
	 * counts as untouched.
	 *
	 * @param mixed $stored Stored blocked_bots value.
	 * @return bool
	 */
	private static function is_legacy_default( mixed $stored ): bool {
		if ( ! is_array( $stored ) ) {
			return false;
		}

		return self::as_set( $stored ) === self::as_set( self::LEGACY_DEFAULT );
	}

	/**
	 * Normalize a bot list into a comparable set.
	 *
	 * @param array<int|string, mixed> $list Bot list.
	 * @return array<int, string>
	 */
	private static function as_set( array $list ): array {
		$normalized = [];

		foreach ( $list as $entry ) {
			$entry = strtolower( trim( (string) $entry ) );

			if ( '' !== $entry ) {
				$normalized[] = $entry;
			}
		}

		$normalized = array_values( array_unique( $normalized ) );
		sort( $normalized );

		return $normalized;
	}
}
