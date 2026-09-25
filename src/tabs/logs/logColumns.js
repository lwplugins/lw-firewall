/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { datetime } from '../../data/format';

// Stored log times are site-local "Y-m-d H:i:s" strings (shown as they
// are); a unix timestamp is formatted in the site timezone.
const logTime = ( value ) =>
	typeof value === 'number' ? datetime( value ) : String( value || '—' );

/**
 * Log table columns. The reason label comes translated from the server; the
 * code stays visible under it for searching docs and the CLI.
 *
 * @return {Array} Columns.
 */
export function logColumns() {
	return [
		{
			id: 'time',
			label: __( 'Time', 'lw-firewall' ),
			render: ( r ) => (
				<span className="lw-admin-nowrap">{ logTime( r.time ) }</span>
			),
		},
		{
			id: 'ip',
			label: __( 'IP', 'lw-firewall' ),
			render: ( r ) => <code className="lw-admin-code">{ r.ip }</code>,
		},
		{
			id: 'reason',
			label: __( 'Reason', 'lw-firewall' ),
			render: ( r ) => (
				<span className="lw-admin-stack">
					<span>{ r.reasonLabel }</span>
					{ r.reasonLabel !== r.reason && (
						<code className="lw-admin-hint">{ r.reason }</code>
					) }
				</span>
			),
		},
		{
			id: 'ua',
			label: __( 'User-Agent', 'lw-firewall' ),
			render: ( r ) => (
				<span className="lw-admin-clip" title={ r.ua }>
					{ r.ua }
				</span>
			),
		},
		{
			id: 'url',
			label: __( 'URL', 'lw-firewall' ),
			render: ( r ) => (
				<code className="lw-admin-code lw-admin-clip" title={ r.url }>
					{ r.url }
				</code>
			),
		},
	];
}
