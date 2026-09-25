/**
 * External dependencies
 */
import { DataTable, useTableState } from '@lwplugins/data-table';
import '@lwplugins/data-table/style.css';

/**
 * WordPress dependencies
 */
import {
	Button,
	// Core has no stable ConfirmDialog yet (same as the sibling LW admins).
	// eslint-disable-next-line @wordpress/no-unsafe-wp-apis
	__experimentalConfirmDialog as ConfirmDialog,
} from '@wordpress/components';
import { useCallback, useMemo, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { update } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import LoadError from '../../components/LoadError';
import Section from '../../components/Section';
import StatTile from '../../components/StatTile';
import StatusBadge from '../../components/StatusBadge';
import { tableLabels } from '../../components/tableLabels';
import { api, errorMessage } from '../../data/api';
import { rangeOf } from '../../data/ranges';
import useRemote from '../../data/useRemote';
import { banColumns } from './banColumns';
import BanForm from './BanForm';
import { reasonOf } from './banLabels';
import UserLocks from './UserLocks';
import useUnban from './useUnban';

/**
 * Confirm text for a pending bulk target.
 *
 * @param {Object|string} pending 'all' | { ips } | { users }.
 * @return {string} Question.
 */
function confirmText( pending ) {
	if ( pending === 'all' ) {
		return __(
			'Lift every ban and username lock, and clear the counters behind them? Addresses that keep attacking will be banned again by the rules.',
			'lw-firewall'
		);
	}
	if ( pending?.users ) {
		return sprintf(
			/* translators: %d: number of locked usernames. */
			_n(
				'Unlock %d username?',
				'Unlock %d usernames?',
				pending.users.length,
				'lw-firewall'
			),
			pending.users.length
		);
	}
	const count = pending?.ips?.length || 0;
	return sprintf(
		/* translators: %d: number of selected bans. */
		_n(
			'Unblock %d selected address and clear its counters?',
			'Unblock %d selected addresses and clear their counters?',
			count,
			'lw-firewall'
		),
		count
	);
}

/**
 * Automatic Bans: summary, manual ban form, searchable/filterable IP table,
 * username locks, single / bulk / "everything" unblock. Every write returns
 * the fresh list, which replaces the table without a refetch.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store (duration range and default).
 */
export default function BansSection( { store } ) {
	const load = useCallback( () => api.bans(), [] );
	const list = useRemote( load );
	const [ selected, setSelected ] = useState( [] );
	const unban = useUnban( list.setData, list.reload, () =>
		setSelected( [] )
	);
	const data = list.data;
	const reasons = data?.reasons || {};
	// Filter fields as strings: `state` (enforced / tracked) and `reasonKey`.
	const items = useMemo(
		() =>
			( data?.items || [] ).map( ( r ) => ( {
				...r,
				state: r.active ? 'enforced' : 'tracked',
				reasonKey: r.reason || 'unknown',
			} ) ),
		[ data ]
	);
	const locks = data?.userLocks || [];

	const columns = banColumns( {
		reasons,
		onUnban: ( r ) => unban.run( { ips: [ r.ip ] }, r.id ),
		unbanning: unban.busy,
	} );
	const table = useTableState( items, {
		searchFields: [ 'ip' ],
		columns,
		sort: { field: 'time', direction: 'desc' },
		perPage: 20,
	} );
	const reasonOptions = Object.values(
		Object.fromEntries(
			items.map( ( r ) => [
				r.reasonKey,
				{ value: r.reasonKey, label: reasonOf( r, reasons )[ 0 ] },
			] )
		)
	);

	return (
		<Section
			title={ __( 'Automatic Bans', 'lw-firewall' ) }
			description={ __(
				'Addresses the firewall banned on its own — brute-force lockouts, registration spam, password-reset floods and rate-limit escalation. Unblocking also clears the counters behind the ban, so the address starts from zero instead of being banned again on its next request.',
				'lw-firewall'
			) }
			badge={
				data ? (
					<StatusBadge
						status={ data.summary.enforced ? 'critical' : 'idle' }
					>
						{ String( data.summary.total + locks.length ) }
					</StatusBadge>
				) : null
			}
			actions={
				<Button
					size="compact"
					variant="tertiary"
					icon={ update }
					label={ __( 'Refresh', 'lw-firewall' ) }
					isBusy={ list.isLoading }
					onClick={ list.reload }
				/>
			}
		>
			{ list.error ? (
				<LoadError
					message={ errorMessage( list.error ) }
					onRetry={ list.reload }
				/>
			) : (
				<>
					{ data && data.summary.total > 0 && (
						<div className="lw-admin-tiles">
							<StatTile
								label={ __( 'Enforced now', 'lw-firewall' ) }
								value={ data.summary.enforced }
							/>
							<StatTile
								label={ __( 'Tracked only', 'lw-firewall' ) }
								value={ data.summary.trackedOnly }
							/>
							<StatTile
								label={ __(
									'Expire within the hour',
									'lw-firewall'
								) }
								value={ data.summary.expiringSoon }
							/>
							<StatTile
								label={ __( 'Ban store', 'lw-firewall' ) }
								value={
									data.store.label ||
									data.store.backend ||
									'—'
								}
							/>
						</div>
					) }
					<BanForm
						range={ rangeOf(
							store.data.meta,
							'auto_ban_duration'
						) }
						fallback={ store.saved.auto_ban_duration }
						onBanned={ list.setData }
					/>
					{ unban.result }
					<DataTable
						columns={ columns }
						table={ table }
						isLoading={ list.isLoading }
						caption={ __( 'Automatic Bans', 'lw-firewall' ) }
						filters={ [
							{
								field: 'reasonKey',
								label: __( 'Reason', 'lw-firewall' ),
								options: reasonOptions,
							},
							{
								field: 'state',
								label: __( 'Status', 'lw-firewall' ),
								multiple: false,
								options: [
									{
										value: 'enforced',
										label: __( 'Enforced', 'lw-firewall' ),
									},
									{
										value: 'tracked',
										label: __(
											'Not enforced',
											'lw-firewall'
										),
									},
								],
							},
						] }
						labels={ {
							...tableLabels(),
							search: __(
								'Search banned IP addresses',
								'lw-firewall'
							),
							empty: __(
								'No banned address matches that search.',
								'lw-firewall'
							),
							emptyAll: `${ __(
								'No addresses are banned right now.',
								'lw-firewall'
							) } ${ __(
								'Bans appear here as soon as the firewall issues one.',
								'lw-firewall'
							) }`,
							selectAll: __(
								'Select all bans on this page',
								'lw-firewall'
							),
						} }
						getRowId={ ( r ) => r.id }
						getRowLabel={ ( r ) => r.ip }
						selection={ { selected, onChange: setSelected } }
						bulkActions={ [
							{
								id: 'unban',
								label: __( 'Unblock selected', 'lw-firewall' ),
								onClick: ( rows, ids ) =>
									unban.ask( {
										ips: items
											.filter( ( r ) =>
												ids.includes( r.id )
											)
											.map( ( r ) => r.ip ),
									} ),
							},
						] }
					/>
					<UserLocks locks={ locks } unban={ unban } />
					{ items.length + locks.length > 0 && (
						<div className="lw-admin-inline">
							<Button
								variant="link"
								isDestructive
								disabled={ !! unban.busy }
								accessibleWhenDisabled
								onClick={ () => unban.ask( 'all' ) }
							>
								{ __(
									'Unblock every banned address',
									'lw-firewall'
								) }
							</Button>
						</div>
					) }
				</>
			) }
			<ConfirmDialog
				isOpen={ !! unban.pending }
				confirmButtonText={ __( 'Unblock', 'lw-firewall' ) }
				onConfirm={ unban.confirm }
				onCancel={ unban.cancel }
			>
				{ confirmText( unban.pending ) }
			</ConfirmDialog>
		</Section>
	);
}
