/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Label + hint of a ban row: the row's own translated reason, else the
 * server's reason map (GET /admin/bans → reasons).
 *
 * @param {Object} row     Ban row.
 * @param {Object} reasons { code: { label, hint } }.
 * @return {Array} [ label, hint ].
 */
export function reasonOf( row, reasons ) {
	const known = reasons[ row.reason ];
	return [
		row.reasonLabel || known?.label || __( 'Unknown', 'lw-firewall' ),
		row.reasonHint || known?.hint || '',
	];
}

/**
 * Subject badge: IPv6 /64 network or legacy (pre-1.5.9) entry.
 *
 * @param {Object} row Ban row.
 * @return {string} Label or ''.
 */
export function kindLabel( row ) {
	if ( row.kind === 'network' ) {
		return __( 'IPv6 /64', 'lw-firewall' );
	}
	return row.kind === 'legacy' ? __( 'Legacy entry', 'lw-firewall' ) : '';
}
