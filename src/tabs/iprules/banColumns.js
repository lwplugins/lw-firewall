/**
 * WordPress dependencies
 */
import { Button } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import StatusBadge from '../../components/StatusBadge';
import { ago, datetime, until } from '../../data/format';
import { kindLabel, reasonOf } from './banLabels';

/**
 * Columns of the Automatic Bans table.
 *
 * @param {Object}   args
 * @param {Object}   args.reasons   Server reason map.
 * @param {Function} args.onUnban   Unblock one row.
 * @param {string}   args.unbanning Busy id of the running unblock ('' idle).
 * @return {Array} Columns.
 */
export function banColumns( { reasons, onUnban, unbanning } ) {
	return [
		{
			id: 'ip',
			label: __( 'IP address', 'lw-firewall' ),
			sortable: true,
			defaultSortDirection: 'asc',
			render: ( r ) => (
				<span className="lw-admin-inline">
					<code className="lw-admin-code">{ r.ip }</code>
					{ kindLabel( r ) && (
						<StatusBadge status="idle">
							{ kindLabel( r ) }
						</StatusBadge>
					) }
				</span>
			),
		},
		{
			id: 'reason',
			label: __( 'Reason', 'lw-firewall' ),
			render: ( r ) => {
				const [ label, hint ] = reasonOf( r, reasons );
				return (
					<span className="lw-admin-stack">
						<span>{ label }</span>
						{ hint && (
							<span className="lw-admin-hint">{ hint }</span>
						) }
					</span>
				);
			},
		},
		{
			id: 'time',
			label: __( 'Banned', 'lw-firewall' ),
			sortable: true,
			render: ( r ) => (
				<span className="lw-admin-stack">
					<strong>{ ago( r.time ) }</strong>
					<span className="lw-admin-hint">
						{ datetime( r.time ) }
					</span>
				</span>
			),
		},
		{
			id: 'expires',
			label: __( 'Expires', 'lw-firewall' ),
			sortable: true,
			render: ( r ) => (
				<span className="lw-admin-stack">
					<strong>{ until( r.expires ) }</strong>
					<span className="lw-admin-hint">
						{ datetime( r.expires ) }
					</span>
				</span>
			),
		},
		{
			id: 'active',
			label: __( 'Status', 'lw-firewall' ),
			render: ( r ) =>
				r.active ? (
					<StatusBadge status="critical">
						{ __( 'Enforced', 'lw-firewall' ) }
					</StatusBadge>
				) : (
					<span
						title={ __(
							'Tracked but no longer enforced — the storage backend was cleared.',
							'lw-firewall'
						) }
					>
						<StatusBadge status="idle">
							{ __( 'Tracked only', 'lw-firewall' ) }
						</StatusBadge>
					</span>
				),
		},
		{
			id: 'actions',
			label: __( 'Actions', 'lw-firewall' ),
			align: 'end',
			render: ( r ) => (
				<Button
					size="compact"
					variant="secondary"
					isBusy={ unbanning === r.id }
					disabled={ !! unbanning }
					accessibleWhenDisabled
					onClick={ () => onUnban( r ) }
				>
					{ __( 'Unblock', 'lw-firewall' ) }
				</Button>
			),
		},
	];
}
