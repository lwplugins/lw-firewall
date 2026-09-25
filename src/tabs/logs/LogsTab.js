/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { SwitchRow } from '../../components/Fields';
import Section from '../../components/Section';
import LogTable from './LogTable';

export default function LogsTab( { store } ) {
	return (
		<>
			<Section title={ __( 'Request Logging', 'lw-firewall' ) }>
				<SwitchRow
					title={ __( 'Enable Logging', 'lw-firewall' ) }
					help={ __(
						'Stores the last 100 blocked requests in the database.',
						'lw-firewall'
					) }
					store={ store }
					name="log_enabled"
					onText={ __( 'Log blocked requests', 'lw-firewall' ) }
					offText={ __( 'Off', 'lw-firewall' ) }
				/>
			</Section>
			<LogTable />
		</>
	);
}
