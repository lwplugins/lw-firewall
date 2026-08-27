<?php
/**
 * Automatic-bans table renderer.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Rules\BanList;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The screen an administrator opens when a customer writes in to say they
 * cannot reach the site: is this address banned, why, and can I let them back
 * in.
 *
 * Every row is rendered up front and the search box, reason filters and pager
 * work on the rendered rows. The table lives inside the settings form, so a
 * `?paged=2` link would navigate away and silently discard unsaved settings on
 * the other tabs. At the index's 500-entry cap the whole list is a few
 * kilobytes of markup.
 */
final class BanTable {

	/**
	 * Render the whole section.
	 *
	 * @return void
	 */
	public static function render(): void {
		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		$rows    = BanList::all( $storage );
		?>
		<h2><?php esc_html_e( 'Automatic Bans', 'lw-firewall' ); ?></h2>
		<p class="lw-firewall-section-description">
			<?php esc_html_e( 'Addresses the firewall banned on its own — brute-force lockouts, registration spam, password-reset floods and rate-limit escalation. Unblocking also clears the counters behind the ban, so the address starts from zero instead of being banned again on its next request.', 'lw-firewall' ); ?>
		</p>

		<?php if ( empty( $rows ) ) : ?>
			<div class="lw-bans-empty">
				<b><?php esc_html_e( 'No addresses are banned right now.', 'lw-firewall' ); ?></b>
				<?php esc_html_e( 'Bans appear here as soon as the firewall issues one.', 'lw-firewall' ); ?>
			</div>
			<?php
			return;
		endif;
		?>

		<div class="lw-bans" data-lw-bans>
			<?php self::render_summary( $rows ); ?>
			<?php self::render_toolbar( $rows ); ?>
			<?php self::render_rows( $rows ); ?>
			<?php self::render_footer(); ?>
		</div>
		<?php
	}

	/**
	 * Counts an administrator needs before reading a single row.
	 *
	 * @param array<int, array<string, mixed>> $rows Ban rows.
	 * @return void
	 */
	private static function render_summary( array $rows ): void {
		$live = 0;
		$soon = 0;
		$now  = time();

		foreach ( $rows as $row ) {
			if ( ! $row['active'] ) {
				continue;
			}

			++$live;

			if ( $row['expires'] - $now < HOUR_IN_SECONDS ) {
				++$soon;
			}
		}

		$cells = [
			[ (string) $live, __( 'Enforced now', 'lw-firewall' ), 'is-critical' ],
			[ (string) ( count( $rows ) - $live ), __( 'Tracked only', 'lw-firewall' ), '' ],
			[ (string) $soon, __( 'Expire within the hour', 'lw-firewall' ), '' ],
			[ (string) Options::get( 'storage', 'auto' ), __( 'Ban store', 'lw-firewall' ), '' ],
		];

		echo '<div class="lw-bans-summary">';

		foreach ( $cells as $cell ) {
			printf(
				'<div class="%s"><b>%s</b><span>%s</span></div>',
				esc_attr( $cell[2] ),
				esc_html( $cell[0] ),
				esc_html( $cell[1] )
			);
		}

		echo '</div>';
	}

	/**
	 * Reason filters and the search box.
	 *
	 * The chip counts come from the whole list, not the visible page, so
	 * "are we under a login attack or a reset flood?" is answered at a glance.
	 *
	 * @param array<int, array<string, mixed>> $rows Ban rows.
	 * @return void
	 */
	private static function render_toolbar( array $rows ): void {
		$counts   = [ 'all' => count( $rows ) ];
		$inactive = 0;

		foreach ( $rows as $row ) {
			$reason            = '' !== $row['reason'] ? $row['reason'] : 'unknown';
			$counts[ $reason ] = ( $counts[ $reason ] ?? 0 ) + 1;

			if ( ! $row['active'] ) {
				++$inactive;
			}
		}

		$chips = [ 'all' => __( 'All', 'lw-firewall' ) ];

		foreach ( array_keys( BanReasons::all() ) as $reason ) {
			if ( isset( $counts[ $reason ] ) ) {
				$chips[ $reason ] = BanReasons::label( $reason );
			}
		}

		if ( isset( $counts['unknown'] ) ) {
			$chips['unknown'] = BanReasons::label( 'unknown' );
		}

		if ( $inactive > 0 ) {
			$chips['inactive']  = __( 'Not enforced', 'lw-firewall' );
			$counts['inactive'] = $inactive;
		}
		?>
		<div class="lw-bans-toolbar">
			<div class="lw-bans-chips" role="group" aria-label="<?php esc_attr_e( 'Filter bans by reason', 'lw-firewall' ); ?>">
				<?php foreach ( $chips as $key => $label ) : ?>
					<button type="button" class="lw-bans-chip" data-lw-ban-filter="<?php echo esc_attr( $key ); ?>" aria-pressed="<?php echo 'all' === $key ? 'true' : 'false'; ?>">
						<?php echo esc_html( $label ); ?>
						<span class="lw-bans-n"><?php echo esc_html( (string) ( $counts[ $key ] ?? 0 ) ); ?></span>
					</button>
				<?php endforeach; ?>
			</div>

			<p class="lw-bans-search">
				<label class="screen-reader-text" for="lw-bans-search"><?php esc_html_e( 'Search banned IP addresses', 'lw-firewall' ); ?></label>
				<input type="search" id="lw-bans-search" data-lw-ban-search autocomplete="off" placeholder="<?php esc_attr_e( 'Search an IP address…', 'lw-firewall' ); ?>" />
			</p>
		</div>
		<?php
	}

	/**
	 * The table itself.
	 *
	 * @param array<int, array<string, mixed>> $rows Ban rows.
	 * @return void
	 */
	private static function render_rows( array $rows ): void {
		?>
		<div class="lw-bans-tablewrap">
			<table class="widefat striped lw-bans-table">
				<thead>
					<tr>
						<td class="check-column"><input type="checkbox" data-lw-ban-all aria-label="<?php esc_attr_e( 'Select all bans on this page', 'lw-firewall' ); ?>" /></td>
						<th><?php esc_html_e( 'IP address', 'lw-firewall' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'lw-firewall' ); ?></th>
						<th><?php esc_html_e( 'Banned', 'lw-firewall' ); ?></th>
						<th><?php esc_html_e( 'Expires', 'lw-firewall' ); ?></th>
						<th><?php esc_html_e( 'Status', 'lw-firewall' ); ?></th>
						<th class="lw-bans-act">&nbsp;</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $rows as $row ) : ?>
						<?php self::render_row( $row ); ?>
					<?php endforeach; ?>
				</tbody>
			</table>
			<p class="lw-bans-nomatch" hidden><?php esc_html_e( 'No banned address matches that search.', 'lw-firewall' ); ?></p>
		</div>
		<?php
	}

	/**
	 * One table row.
	 *
	 * @param array<string, mixed> $row Ban row.
	 * @return void
	 */
	private static function render_row( array $row ): void {
		$reason = '' !== $row['reason'] ? (string) $row['reason'] : 'unknown';
		?>
		<tr data-lw-ban-row data-ip="<?php echo esc_attr( $row['ip'] ); ?>" data-reason="<?php echo esc_attr( $reason ); ?>" data-active="<?php echo $row['active'] ? '1' : '0'; ?>" class="<?php echo $row['active'] ? '' : 'lw-bans-dim'; ?>">
			<th scope="row" class="check-column">
				<input type="checkbox" name="lw_firewall_unban_ips[]" value="<?php echo esc_attr( $row['ip'] ); ?>" data-lw-ban-check aria-label="<?php echo esc_attr( sprintf( /* translators: %s: IP address. */ __( 'Select %s', 'lw-firewall' ), $row['ip'] ) ); ?>" />
			</th>
			<td class="lw-bans-ip"><code><?php echo esc_html( $row['ip'] ); ?></code></td>
			<td>
				<span class="lw-bans-reason">
					<?php echo esc_html( BanReasons::label( $reason ) ); ?>
					<span><?php echo esc_html( BanReasons::hint( $reason ) ); ?></span>
				</span>
			</td>
			<td class="lw-bans-when">
				<b><?php echo esc_html( self::ago( (int) $row['time'] ) ); ?></b>
				<?php echo esc_html( $row['time'] > 0 ? wp_date( 'Y-m-d H:i', (int) $row['time'] ) : '—' ); ?>
			</td>
			<td class="lw-bans-when">
				<b><?php echo esc_html( self::until( (int) $row['expires'] ) ); ?></b>
				<?php echo esc_html( wp_date( 'Y-m-d H:i', (int) $row['expires'] ) ); ?>
			</td>
			<td>
				<?php if ( $row['active'] ) : ?>
					<span class="lw-bans-pill is-live"><?php esc_html_e( 'Enforced', 'lw-firewall' ); ?></span>
				<?php else : ?>
					<span class="lw-bans-pill is-gone" title="<?php esc_attr_e( 'Tracked but no longer enforced — the storage backend was cleared.', 'lw-firewall' ); ?>"><?php esc_html_e( 'Tracked only', 'lw-firewall' ); ?></span>
				<?php endif; ?>
			</td>
			<td class="lw-bans-act">
				<button type="submit" name="lw_firewall_unban" value="<?php echo esc_attr( $row['ip'] ); ?>" class="button button-small">
					<?php esc_html_e( 'Unblock', 'lw-firewall' ); ?>
				</button>
			</td>
		</tr>
		<?php
	}

	/**
	 * Bulk action, result count and the pager.
	 *
	 * @return void
	 */
	private static function render_footer(): void {
		?>
		<div class="lw-bans-foot">
			<div class="lw-bans-bulk">
				<button type="submit" name="lw_firewall_unban" value="__selected__" class="button" data-lw-ban-bulk disabled>
					<?php esc_html_e( 'Unblock selected', 'lw-firewall' ); ?>
				</button>
				<span class="lw-bans-selcount" data-lw-ban-selcount></span>
			</div>
			<div class="lw-bans-pager" data-lw-ban-pager></div>
		</div>

		<p class="lw-bans-all">
			<button type="submit" name="lw_firewall_unban" value="__all__" class="button-link lw-bans-danger">
				<?php esc_html_e( 'Unblock every banned address', 'lw-firewall' ); ?>
			</button>
		</p>
		<?php
	}

	/**
	 * "12 mins ago" — answers whether the ban is fresh.
	 *
	 * @param int $time Ban timestamp.
	 * @return string
	 */
	private static function ago( int $time ): string {
		if ( $time <= 0 ) {
			return __( 'unknown', 'lw-firewall' );
		}

		/* translators: %s: human-readable time difference, e.g. "12 mins". */
		return sprintf( __( '%s ago', 'lw-firewall' ), human_time_diff( $time ) );
	}

	/**
	 * "in 24 mins" — answers whether a click is even needed.
	 *
	 * @param int $expires Expiry timestamp.
	 * @return string
	 */
	private static function until( int $expires ): string {
		if ( $expires <= time() ) {
			return __( 'expired', 'lw-firewall' );
		}

		/* translators: %s: human-readable time difference, e.g. "24 mins". */
		return sprintf( __( 'in %s', 'lw-firewall' ), human_time_diff( time(), $expires ) );
	}
}
