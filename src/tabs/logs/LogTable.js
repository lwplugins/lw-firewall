/**
 * External dependencies
 */
import { DataTable, DEFAULT_QUERY } from '@lwplugins/data-table';
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
import { useDispatch } from '@wordpress/data';
import { useEffect, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { trash, update } from '@wordpress/icons';
import { store as noticesStore } from '@wordpress/notices';

/**
 * Internal dependencies
 */
import Callout from '../../components/Callout';
import Section from '../../components/Section';
import { tableLabels } from '../../components/tableLabels';
import { api, errorMessage } from '../../data/api';
import { logColumns } from './logColumns';

const EMPTY = {
	items: [],
	total: 0,
	totalPages: 1,
	reasons: [],
	enabled: true,
};

/**
 * Blocked-request log, server-paged (GET /admin/logs), with a reason filter,
 * search, refresh and "Clear log" (asks first).
 */
export default function LogTable() {
	const [ query, setQuery ] = useState( {
		...DEFAULT_QUERY,
		perPage: 20,
	} );
	const [ result, setResult ] = useState( EMPTY );
	const [ loading, setLoading ] = useState( true );
	const [ error, setError ] = useState( null );
	const [ tick, setTick ] = useState( 0 );
	const [ confirming, setConfirming ] = useState( false );
	const { createSuccessNotice, createErrorNotice } =
		useDispatch( noticesStore );
	const reload = () => setTick( ( t ) => t + 1 );

	useEffect( () => {
		// Abort the previous request so a slow answer never wins.
		const controller = new AbortController();
		setLoading( true );
		api.logs(
			{
				page: query.page,
				perPage: query.perPage,
				reason: query.filters?.reason?.[ 0 ],
				search: query.search,
			},
			controller.signal
		)
			.then( ( data ) => {
				setResult( data );
				setError( null );
			} )
			.catch(
				( e ) =>
					e.name !== 'AbortError' && setError( errorMessage( e ) )
			)
			.finally(
				() => ! controller.signal.aborted && setLoading( false )
			);
		return () => controller.abort();
	}, [ query, tick ] );

	const clear = async () => {
		setConfirming( false );
		try {
			const r = await api.clearLogs();
			createSuccessNotice(
				r?.message || __( 'Log cleared.', 'lw-firewall' ),
				{ type: 'snackbar' }
			);
			setQuery( ( q ) => ( { ...q, page: 1 } ) );
			reload();
		} catch ( e ) {
			createErrorNotice( errorMessage( e ), { type: 'snackbar' } );
		}
	};

	return (
		<Section
			title={ __( 'Blocked requests', 'lw-firewall' ) }
			actions={
				<div className="lw-admin-inline">
					<Button
						size="compact"
						variant="tertiary"
						icon={ update }
						label={ __( 'Refresh', 'lw-firewall' ) }
						isBusy={ loading }
						onClick={ reload }
					/>
					<Button
						size="compact"
						variant="secondary"
						isDestructive
						icon={ trash }
						disabled={ ! result.total }
						accessibleWhenDisabled
						onClick={ () => setConfirming( true ) }
					>
						{ __( 'Clear log', 'lw-firewall' ) }
					</Button>
				</div>
			}
		>
			{ ! loading && ! result.enabled && (
				<Callout tone="warning">
					{ __(
						'Logging is off, so no new blocked requests are recorded. Turn on "Log blocked requests" above and save.',
						'lw-firewall'
					) }
				</Callout>
			) }
			<DataTable
				columns={ logColumns() }
				rows={ result.items }
				total={ result.total }
				totalPages={ result.totalPages }
				query={ query }
				onQueryChange={ setQuery }
				isLoading={ loading }
				error={ error }
				errorAction={
					<Button variant="secondary" onClick={ reload }>
						{ __( 'Try again', 'lw-firewall' ) }
					</Button>
				}
				caption={ __( 'Blocked requests', 'lw-firewall' ) }
				filters={
					result.reasons.length
						? [
								{
									field: 'reason',
									label: __( 'Reason', 'lw-firewall' ),
									options: result.reasons,
									multiple: false,
								},
							]
						: []
				}
				labels={ {
					...tableLabels(),
					search: __( 'Search IP, URL or User-Agent', 'lw-firewall' ),
					emptyAll: __( 'No log entries yet.', 'lw-firewall' ),
				} }
				getRowId={ ( r ) => r.id }
				perPageOptions={ [ 20, 50, 100 ] }
			/>
			<ConfirmDialog
				isOpen={ confirming }
				confirmButtonText={ __( 'Clear log', 'lw-firewall' ) }
				onConfirm={ clear }
				onCancel={ () => setConfirming( false ) }
			>
				{ __(
					'Delete every log entry? This cannot be undone.',
					'lw-firewall'
				) }
			</ConfirmDialog>
		</Section>
	);
}
