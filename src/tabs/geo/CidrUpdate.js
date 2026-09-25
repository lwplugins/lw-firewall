/**
 * WordPress dependencies
 */
import { Button } from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { update } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import Callout from '../../components/Callout';
import ResultBox from '../../components/ResultBox';
import SettingRow from '../../components/SettingRow';
import StatusBadge from '../../components/StatusBadge';
import { api, errorMessage } from '../../data/api';
import { datetime, until } from '../../data/format';
import GeoFreshness from './GeoFreshness';

const listBadge = ( ok ) => (
	<StatusBadge status={ ok ? 'ok' : 'critical' }>
		{ ok ? __( 'Updated', 'lw-firewall' ) : __( 'Failed', 'lw-firewall' ) }
	</StatusBadge>
);

/**
 * "Update CIDR Lists Now": one request per SAVED country (never the draft),
 * one after the other, so each request stays short; progress "n of m".
 *
 * @param {Object} props
 * @param {Object} props.store  Settings store.
 * @param {Object} props.status Status remote (freshness, next update).
 */
export default function CidrUpdate( { store, status } ) {
	const [ progress, setProgress ] = useState( null ); // { done, total }
	const [ results, setResults ] = useState( null );
	const { meta } = store.data;
	const names = Object.fromEntries(
		meta.countries.map( ( c ) => [ c.code, c.name ] )
	);
	const saved = store.saved.blocked_countries || [];
	const next = status.data?.geo.nextUpdate || meta.geoNextUpdate;

	const run = async () => {
		const done = [];
		setResults( null );
		for ( let i = 0; i < saved.length; i++ ) {
			setProgress( { done: i + 1, total: saved.length } );
			try {
				const r = await api.updateGeo( saved[ i ] );
				done.push(
					...( r.results.length
						? r.results
						: [
								{
									cc: saved[ i ],
									v4: false,
									v6: false,
									message: r.message,
								},
							] )
				);
			} catch ( e ) {
				done.push( {
					cc: saved[ i ],
					v4: false,
					v6: false,
					message: errorMessage( e ),
				} );
			}
		}
		setProgress( null );
		setResults( done );
		status.reload();
	};

	const failed = results?.filter( ( r ) => ! r.v4 || ! r.v6 ) || [];

	return (
		<SettingRow
			title={ __( 'Country IP lists', 'lw-firewall' ) }
			help={
				next
					? sprintf(
							/* translators: %s: relative time of the next automatic update. */
							__( 'Next automatic update: %s', 'lw-firewall' ),
							`${ until( next ) } (${ datetime( next ) })`
						)
					: __(
							'Without Cloudflare, visitors are matched against downloaded IPv4 and IPv6 lists per country.',
							'lw-firewall'
						)
			}
		>
			{ meta.cloudflare && (
				<Callout>
					{ __(
						'Cloudflare detected: the CF-IPCountry header decides, so these lists are only a fallback.',
						'lw-firewall'
					) }
				</Callout>
			) }
			<GeoFreshness status={ status } names={ names } />
			<div className="lw-admin-inline">
				<Button
					__next40pxDefaultSize
					variant="secondary"
					icon={ update }
					isBusy={ !! progress }
					disabled={ !! progress || ! saved.length }
					accessibleWhenDisabled
					onClick={ run }
				>
					{ __( 'Update CIDR Lists Now', 'lw-firewall' ) }
				</Button>
				{ progress && (
					<span className="lw-admin-hint" role="status">
						{ sprintf(
							/* translators: 1: current country number, 2: number of countries. */
							__( 'Updating %1$d of %2$d…', 'lw-firewall' ),
							progress.done,
							progress.total
						) }
					</span>
				) }
			</div>
			{ store.isDirty( 'blocked_countries' ) && (
				<Callout tone="warning">
					{ __(
						'Save your changes first: the update downloads the lists of the saved countries.',
						'lw-firewall'
					) }
				</Callout>
			) }
			{ results && (
				<ResultBox
					tone={ failed.length ? 'warning' : 'ok' }
					message={
						failed.length
							? __(
									'Some lists could not be downloaded. The previous list is kept for those.',
									'lw-firewall'
								)
							: __(
									'All country lists are up to date.',
									'lw-firewall'
								)
					}
				>
					<table className="lw-admin-mini">
						<thead>
							<tr>
								<th>{ __( 'Country', 'lw-firewall' ) }</th>
								<th>IPv4</th>
								<th>IPv6</th>
								<th>{ __( 'Details', 'lw-firewall' ) }</th>
							</tr>
						</thead>
						<tbody>
							{ results.map( ( r ) => (
								<tr key={ r.cc }>
									<td>
										<code>{ r.cc }</code>{ ' ' }
										{ names[ r.cc ] || '' }
									</td>
									<td>{ listBadge( r.v4 ) }</td>
									<td>{ listBadge( r.v6 ) }</td>
									<td>{ r.message }</td>
								</tr>
							) ) }
						</tbody>
					</table>
				</ResultBox>
			) }
		</SettingRow>
	);
}
