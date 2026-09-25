/**
 * WordPress dependencies
 */
import { Notice } from '@wordpress/components';
import { __, _n, sprintf } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import KeyValue from '../../components/KeyValue';
import LoadError from '../../components/LoadError';
import Section from '../../components/Section';
import { SkeletonRows } from '../../components/skeleton';
import { datetime } from '../../data/format';
import { errorMessage } from '../../data/api';

/**
 * Alerts status block (inventory §5.2), from GET /admin/status → alerts.
 *
 * @param {Object} props
 * @param {Object} props.status Status remote.
 */
export default function AlertStatus( { status } ) {
	let body;
	if ( status.error ) {
		body = (
			<LoadError
				message={ errorMessage( status.error ) }
				onRetry={ status.reload }
			/>
		);
	} else if ( ! status.data ) {
		body = <SkeletonRows count={ 4 } />;
	} else {
		const a = status.data.alerts;
		body = (
			<>
				{ a.pending > 0 && (
					<Notice status="warning" isDismissible={ false }>
						{ sprintf(
							/* translators: %d: number of queued alerts. */
							_n(
								'%d alert could not be sent yet and will be retried on the next scan.',
								'%d alerts could not be sent yet and will be retried on the next scan.',
								a.pending,
								'lw-firewall'
							),
							a.pending
						) }
					</Notice>
				) }
				{ a.mailError && (
					<Notice status="warning" isDismissible={ false }>
						{ __(
							'The last alert email could not be sent. Check your site mail configuration (SMTP plugin, hosting mail limits) — an alert that never arrives is no alert at all.',
							'lw-firewall'
						) }
					</Notice>
				) }
				<KeyValue
					rows={ [
						{
							label: __(
								'Administrators tracked',
								'lw-firewall'
							),
							value:
								a.adminsTracked === null
									? '—'
									: String( a.adminsTracked ),
						},
						{
							label: __( 'Alerts go to', 'lw-firewall' ),
							value: a.recipients || '—',
						},
						{
							label: __( 'Snapshot taken', 'lw-firewall' ),
							value: a.snapshot
								? datetime( a.snapshot )
								: __(
										'never — taken on the first scan',
										'lw-firewall'
									),
						},
						{
							label: __( 'Next scan', 'lw-firewall' ),
							value: a.nextScan
								? datetime( a.nextScan )
								: __( 'not scheduled', 'lw-firewall' ),
						},
					] }
				/>
			</>
		);
	}

	return <Section title={ __( 'Status', 'lw-firewall' ) }>{ body }</Section>;
}
