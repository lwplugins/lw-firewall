/**
 * WordPress dependencies
 */
import { Button } from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { envelope, search } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import Callout from '../../components/Callout';
import ResultBox from '../../components/ResultBox';
import SettingRow from '../../components/SettingRow';
import { api, errorMessage } from '../../data/api';

const KEYS = [
	'admin_alert_enabled',
	'admin_alert_email',
	'admin_alert_changes',
	'admin_alert_scan_enabled',
];

/**
 * Scan result → tone + honest message. The server message wins; the
 * fallbacks never claim "clean" while alerts are off or "sent" when queued.
 *
 * @param {Object} r toScanResult().
 * @return {Array} [ tone, message ].
 */
function scanOutcome( r ) {
	if ( r.state === 'disabled' ) {
		return [
			'warning',
			r.message ||
				__(
					'Alerts are turned off, so nothing was scanned. Enable alerts and save first.',
					'lw-firewall'
				),
		];
	}
	if ( r.state === 'clean' ) {
		return [
			'ok',
			r.message ||
				__(
					'Scan finished: no new or modified administrators found.',
					'lw-firewall'
				),
		];
	}
	if ( r.sent ) {
		return [
			'warning',
			r.message ||
				__(
					'Scan finished: new or modified administrators were found and an alert email was sent.',
					'lw-firewall'
				),
		];
	}
	return [
		'error',
		r.message ||
			__(
				'Scan finished: new or modified administrators were found, but the alert email could not be sent yet. It is queued and retried on the next scan.',
				'lw-firewall'
			),
	];
}

function testOutcome( r ) {
	if ( r.sent ) {
		return [
			'ok',
			r.message ||
				__(
					'Test alert sent. If it does not arrive, the problem is your site mail configuration, not the firewall.',
					'lw-firewall'
				),
		];
	}
	return [
		'error',
		r.error ||
			r.message ||
			__(
				'The test alert could not be sent — wp_mail() refused it. Check your SMTP plugin or hosting mail limits.',
				'lw-firewall'
			),
	];
}

/**
 * "Run scan now" / "Send test email". They act on the SAVED settings and
 * never save the draft, so unsaved alert edits get a hint.
 *
 * @param {Object}   props
 * @param {Object}   props.store  Settings store.
 * @param {Function} props.onDone Refresh the status block.
 */
export default function AlertActions( { store, onDone } ) {
	const [ busy, setBusy ] = useState( '' );
	const [ result, setResult ] = useState( null );

	const run = async ( which ) => {
		setBusy( which );
		setResult( null );
		try {
			const r =
				which === 'scan'
					? await api.scanAlerts()
					: await api.testAlert();
			setResult( which === 'scan' ? scanOutcome( r ) : testOutcome( r ) );
			onDone();
		} catch ( e ) {
			setResult( [ 'error', errorMessage( e ) ] );
		}
		setBusy( '' );
	};

	return (
		<SettingRow
			title={ __( 'Check it now', 'lw-firewall' ) }
			help={ __(
				'Run the database scan immediately, or send a test message to the saved recipients.',
				'lw-firewall'
			) }
		>
			<div className="lw-admin-inline">
				<Button
					__next40pxDefaultSize
					variant="secondary"
					icon={ search }
					isBusy={ busy === 'scan' }
					disabled={ !! busy }
					accessibleWhenDisabled
					onClick={ () => run( 'scan' ) }
				>
					{ __( 'Run scan now', 'lw-firewall' ) }
				</Button>
				<Button
					__next40pxDefaultSize
					variant="secondary"
					icon={ envelope }
					isBusy={ busy === 'test' }
					disabled={ !! busy }
					accessibleWhenDisabled
					onClick={ () => run( 'test' ) }
				>
					{ __( 'Send test email', 'lw-firewall' ) }
				</Button>
			</div>
			{ KEYS.some( store.isDirty ) && (
				<Callout tone="warning">
					{ __(
						'You have unsaved alert changes. The scan and the test email use the saved settings, so save first.',
						'lw-firewall'
					) }
				</Callout>
			) }
			{ result && (
				<ResultBox tone={ result[ 0 ] } message={ result[ 1 ] } />
			) }
		</SettingRow>
	);
}
