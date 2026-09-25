/**
 * WordPress dependencies
 */
import { Button, Notice } from '@wordpress/components';
import { useEffect } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { update } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import LoadError from '../../components/LoadError';
import Section from '../../components/Section';
import StatusBadge from '../../components/StatusBadge';
import {
	SkeletonRegion,
	SkeletonRows,
	SkeletonSection,
} from '../../components/skeleton';
import { errorMessage } from '../../data/api';
import GeoBlock from './GeoBlock';
import IpBlock from './IpBlock';
import StorageBlock from './StorageBlock';
import VersionsBlock from './VersionsBlock';
import WorkerBlock from './WorkerBlock';

const NOTICE = { error: 'error', critical: 'error', warning: 'warning' };

function StatusSkeleton() {
	return (
		<SkeletonRegion className="lw-skel-tab">
			{ [ 4, 3, 5 ].map( ( count ) => (
				<SkeletonSection key={ count } description={ false }>
					<SkeletonRows count={ count } />
				</SkeletonSection>
			) ) }
		</SkeletonRegion>
	);
}

/**
 * Status: warnings first, then worker, storage probe, client IP diagnosis,
 * geo lists and versions. Re-fetched every time the tab opens (the probe is live).
 *
 * @param {Object} props
 * @param {Object} props.status Status remote (shared with the nav badge).
 */
export default function StatusTab( { status } ) {
	useEffect( () => {
		// The app fetched once on load (nav badge); refresh on every visit
		// after that, unless that first request is still running.
		if ( status.data ) {
			status.reload();
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [] );

	if ( status.error ) {
		return (
			<LoadError
				message={ errorMessage( status.error ) }
				onRetry={ status.reload }
			/>
		);
	}
	if ( ! status.data ) {
		return <StatusSkeleton />;
	}

	const s = status.data;

	return (
		<>
			<Section
				title={ __( 'Firewall Status', 'lw-firewall' ) }
				badge={
					! s.firewall.enabled ? (
						<StatusBadge status="critical">
							{ __( 'Firewall off', 'lw-firewall' ) }
						</StatusBadge>
					) : null
				}
				actions={
					<Button
						size="compact"
						variant="tertiary"
						icon={ update }
						isBusy={ status.isLoading }
						onClick={ status.reload }
					>
						{ __( 'Refresh', 'lw-firewall' ) }
					</Button>
				}
			>
				{ s.warnings.length === 0 ? (
					<p className="lw-admin-muted">
						{ __(
							'No problems found. The worker, storage and client IP detection all look healthy.',
							'lw-firewall'
						) }
					</p>
				) : (
					s.warnings.map( ( w, index ) => (
						<Notice
							key={ w.code || index }
							status={ NOTICE[ w.severity ] || 'info' }
							isDismissible={ false }
						>
							{ w.message }
						</Notice>
					) )
				) }
			</Section>
			<WorkerBlock worker={ s.worker } onChanged={ status.reload } />
			<StorageBlock storage={ s.storage } />
			<IpBlock ip={ s.ip } />
			<GeoBlock geo={ s.geo } />
			<VersionsBlock firewall={ s.firewall } worker={ s.worker } />
		</>
	);
}
