/**
 * WordPress dependencies
 */
import { __, _n, sprintf } from '@wordpress/i18n';

/**
 * Translated UI strings for `@lwplugins/data-table` (it has no text domain).
 *
 * @return {Object} Labels.
 */
export function tableLabels() {
	return {
		search: __( 'Search', 'lw-firewall' ),
		filter: __( 'Filter', 'lw-firewall' ),
		clear: __( 'Clear', 'lw-firewall' ),
		clearAll: __( 'Clear all filters', 'lw-firewall' ),
		all: __( 'All', 'lw-firewall' ),
		empty: __( 'No entries match these filters.', 'lw-firewall' ),
		emptyAll: __( 'Nothing here yet.', 'lw-firewall' ),
		loading: __( 'Loading…', 'lw-firewall' ),
		previous: __( 'Previous page', 'lw-firewall' ),
		next: __( 'Next page', 'lw-firewall' ),
		perPage: __( 'Rows per page', 'lw-firewall' ),
		selectAll: __( 'Select all rows on this page', 'lw-firewall' ),
		clearSelection: __( 'Clear selection', 'lw-firewall' ),
		bulkActions: __( 'Bulk actions', 'lw-firewall' ),
		entries: ( n ) =>
			sprintf(
				/* translators: %d: number of rows. */ _n(
					'%d entry',
					'%d entries',
					n,
					'lw-firewall'
				),
				n
			),
		results: ( n ) =>
			sprintf(
				/* translators: %d: number of results. */ _n(
					'%d result',
					'%d results',
					n,
					'lw-firewall'
				),
				n
			),
		page: ( p, t ) =>
			sprintf(
				/* translators: 1: current page, 2: total pages. */ __(
					'Page %1$d of %2$d',
					'lw-firewall'
				),
				p,
				t
			),
		selectRow: ( label ) =>
			sprintf(
				/* translators: %s: row name. */ __(
					'Select: %s',
					'lw-firewall'
				),
				label
			),
		selected: ( n, onPage ) =>
			n === onPage
				? sprintf(
						/* translators: %d: number of selected rows. */
						_n( '%d selected', '%d selected', n, 'lw-firewall' ),
						n
					)
				: sprintf(
						/* translators: 1: selected rows, 2: of those, on this page. */
						__( '%1$d selected, %2$d on this page', 'lw-firewall' ),
						n,
						onPage
					),
		eligible: ( e, n ) =>
			sprintf(
				/* translators: 1: rows the action applies to, 2: selected rows on this page. */ __(
					'applies to %1$d of %2$d',
					'lw-firewall'
				),
				e,
				n
			),
	};
}
