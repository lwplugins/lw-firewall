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
import KeyValue from '../../components/KeyValue';
import ResultBox from '../../components/ResultBox';
import Section from '../../components/Section';
import StatusBadge from '../../components/StatusBadge';
import { api, errorMessage } from '../../data/api';
import { age, ago } from '../../data/format';
import yesNo from './yesNo';

function versionValue( worker ) {
	if ( ! worker.version ) {
		return '—';
	}
	return (
		<span className="lw-admin-inline">
			<code>{ worker.version }</code>
			{ worker.versionMatch ? (
				<StatusBadge status="ok">
					{ __( 'Matches the plugin', 'lw-firewall' ) }
				</StatusBadge>
			) : (
				<StatusBadge status="critical">
					{ sprintf(
						/* translators: %s: expected worker version. */
						__(
							'Mismatch — expected %s (will auto-update on next page load)',
							'lw-firewall'
						),
						worker.expected
					) }
				</StatusBadge>
			) }
		</span>
	);
}

function attemptValue( attempt ) {
	if ( ! attempt ) {
		return null;
	}
	return (
		<span className="lw-admin-stack">
			<StatusBadge status={ attempt.success ? 'ok' : 'critical' }>
				{ attempt.success
					? __( 'Succeeded', 'lw-firewall' )
					: __( 'Failed', 'lw-firewall' ) }
			</StatusBadge>
			{ ! attempt.success && attempt.message && (
				<span>{ attempt.message }</span>
			) }
			{ attempt.time > 0 && (
				<span className="lw-admin-hint">{ ago( attempt.time ) }</span>
			) }
		</span>
	);
}

/**
 * MU-plugin worker health + "Reinstall worker" (its own action; the result
 * comes back as a sentence, never a raw error code).
 *
 * @param {Object}   props
 * @param {Object}   props.worker    Status worker block.
 * @param {Function} props.onChanged Reload the status after a reinstall.
 */
export default function WorkerBlock( { worker, onChanged } ) {
	const [ busy, setBusy ] = useState( false );
	const [ result, setResult ] = useState( null );

	const reinstall = async () => {
		setBusy( true );
		setResult( null );
		try {
			const r = await api.reinstallWorker();
			setResult( [
				r.ok ? 'ok' : 'error',
				r.message ||
					( r.ok
						? __( 'The worker was reinstalled.', 'lw-firewall' )
						: __( 'Unknown install error.', 'lw-firewall' ) ),
			] );
			onChanged();
		} catch ( e ) {
			setResult( [ 'error', errorMessage( e ) ] );
		}
		setBusy( false );
	};

	return (
		<Section
			title={ __( 'MU-Plugin Worker', 'lw-firewall' ) }
			description={ __(
				'The MU-plugin worker intercepts requests early, before themes and plugins load.',
				'lw-firewall'
			) }
			actions={
				<Button
					size="compact"
					variant="secondary"
					icon={ update }
					isBusy={ busy }
					disabled={ busy }
					accessibleWhenDisabled
					onClick={ reinstall }
				>
					{ __( 'Reinstall worker', 'lw-firewall' ) }
				</Button>
			}
		>
			{ result && (
				<ResultBox tone={ result[ 0 ] } message={ result[ 1 ] } />
			) }
			<KeyValue
				rows={ [
					{
						label: __( 'Worker file', 'lw-firewall' ),
						value: (
							<StatusBadge
								status={ worker.installed ? 'ok' : 'critical' }
							>
								{ worker.installed
									? __( 'Installed', 'lw-firewall' )
									: __( 'Not installed', 'lw-firewall' ) }
							</StatusBadge>
						),
					},
					{
						label: __( 'Worker Version', 'lw-firewall' ),
						value: versionValue( worker ),
					},
					{
						label: __( 'mu-plugins writable', 'lw-firewall' ),
						value: ! worker.muWritable ? (
							<StatusBadge status="warning">
								{ sprintf(
									/* translators: %s: mu-plugins directory. */
									__(
										'No — make %s writable by the web server.',
										'lw-firewall'
									),
									worker.muDir || 'wp-content/mu-plugins'
								) }
							</StatusBadge>
						) : (
							yesNo( true )
						),
					},
					{
						label: __( 'Last heartbeat', 'lw-firewall' ),
						value:
							worker.heartbeatAge === null
								? __( 'never', 'lw-firewall' )
								: age( worker.heartbeatAge ),
					},
					worker.killSwitch && {
						label: __( 'Kill switch', 'lw-firewall' ),
						value: (
							<StatusBadge status="critical">
								LW_FIREWALL_DISABLE_WORKER
							</StatusBadge>
						),
					},
					worker.lastAttempt && {
						label: __( 'Last install attempt', 'lw-firewall' ),
						value: attemptValue( worker.lastAttempt ),
					},
				] }
			/>
		</Section>
	);
}
