/**
 * WordPress dependencies
 */
import { __, sprintf } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import Callout from '../../components/Callout';
import LoadError from '../../components/LoadError';
import Section from '../../components/Section';
import {
	SkeletonRegion,
	SkeletonRows,
	SkeletonSection,
} from '../../components/skeleton';
import StatTile from '../../components/StatTile';
import StatusBadge from '../../components/StatusBadge';
import { errorMessage } from '../../data/api';

function Loading() {
	return (
		<SkeletonRegion className="lw-skel-tab">
			<SkeletonSection description={ false }>
				<SkeletonRows count={ 4 } />
			</SkeletonSection>
		</SkeletonRegion>
	);
}

/**
 * Who already uses a second factor, per role (counts only).
 *
 * @param {Object} props
 * @param {Object} props.summary useRemote state of the summary endpoint.
 */
export default function AdoptionSection( { summary } ) {
	if ( summary.error ) {
		return (
			<LoadError
				message={ errorMessage( summary.error ) }
				onRetry={ summary.reload }
			/>
		);
	}
	if ( ! summary.data ) {
		return <Loading />;
	}

	const s = summary.data;
	const percent = s.totalUsers
		? Math.round( ( s.totalWith2fa / s.totalUsers ) * 100 )
		: 0;
	const atLeast = s.truncated ? '≥ ' : '';

	return (
		<Section
			title={ __( 'Who Uses It', 'lw-firewall' ) }
			description={ __(
				'Users with an authenticator app or a passkey, per role.',
				'lw-firewall'
			) }
		>
			<div className="lw-admin-tiles">
				<StatTile
					label={ __( 'With two-factor', 'lw-firewall' ) }
					value={ `${ atLeast }${ s.totalWith2fa }` }
					detail={ sprintf(
						/* translators: %d: total number of users. */
						__( 'of %d users', 'lw-firewall' ),
						s.totalUsers
					) }
					meter={ percent }
				/>
				<StatTile
					label={ __( 'Passkeys', 'lw-firewall' ) }
					value={
						s.passkeysAvailable
							? __( 'Available', 'lw-firewall' )
							: __( 'Not available', 'lw-firewall' )
					}
					detail={
						s.passkeysAvailable
							? ''
							: __(
									'This server or site address cannot use passkeys.',
									'lw-firewall'
								)
					}
				/>
			</div>
			{ ! s.cryptoAvailable && (
				<Callout tone="warning">
					{ __(
						'The PHP sodium and openssl extensions are required for two-factor login, and this server is missing at least one of them. Two-factor login stays off until they are enabled.',
						'lw-firewall'
					) }
				</Callout>
			) }
			<table className="lw-admin-mini">
				<thead>
					<tr>
						<th>{ __( 'Role', 'lw-firewall' ) }</th>
						<th>{ __( 'Users', 'lw-firewall' ) }</th>
						<th>{ __( 'With two-factor', 'lw-firewall' ) }</th>
						<th>{ __( 'Required', 'lw-firewall' ) }</th>
					</tr>
				</thead>
				<tbody>
					{ s.roles.map( ( r ) => (
						<tr key={ r.role }>
							<td>{ r.label }</td>
							<td>{ r.users }</td>
							<td>{ r.with2fa }</td>
							<td>
								{ r.required ? (
									<StatusBadge status="info">
										{ __( 'Required', 'lw-firewall' ) }
									</StatusBadge>
								) : (
									'—'
								) }
							</td>
						</tr>
					) ) }
				</tbody>
			</table>
			{ s.truncated && (
				<p className="lw-admin-hint">
					{ __(
						'Large site: only the first accounts with a second factor were counted, so the numbers are a lower bound.',
						'lw-firewall'
					) }
				</p>
			) }
		</Section>
	);
}
