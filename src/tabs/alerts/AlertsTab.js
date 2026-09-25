/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { SwitchRow, TextRow } from '../../components/Fields';
import KeyValue from '../../components/KeyValue';
import Section from '../../components/Section';
import AlertActions from './AlertActions';
import AlertStatus from './AlertStatus';

const detection = () => [
	{
		key: 'hooks',
		label: __( 'WordPress hooks', 'lw-firewall' ),
		value: __(
			'Immediate. Catches every account creation or role change that goes through the WordPress user API — the Users screen, user registration, the REST API, WP-CLI, and any plugin or theme calling wp_insert_user() or set_role(). The alert names the acting user and their IP address.',
			'lw-firewall'
		),
	},
	{
		key: 'scan',
		label: __( 'Database scan', 'lw-firewall' ),
		value: __(
			'Within the hour. A snapshot of every administrator user ID is stored, and the scheduled scan diffs it against the live list. Anything that appears without a hook firing — a direct SQL INSERT, a modified wp_capabilities meta row, an account added while the plugin was off — shows up here and is flagged as created outside the normal WordPress flow.',
			'lw-firewall'
		),
	},
	{
		key: 'snapshot',
		label: __( 'What the snapshot stores', 'lw-firewall' ),
		value: __(
			'Per administrator: the user ID, the username, the email address, and a digest of the stored password hash. The digest only ever answers "did this change?" — the password itself is never stored, never compared and never printed in an alert.',
			'lw-firewall'
		),
	},
	{
		key: 'dupes',
		label: __( 'No duplicate alerts', 'lw-firewall' ),
		value: __(
			'Both paths write to the same snapshot, so each event is reported exactly once. Existing administrators are recorded silently when the feature is turned on — you are only told about what happens afterwards. Removing an administrator is not reported; the account simply leaves the snapshot.',
			'lw-firewall'
		),
	},
];

export default function AlertsTab( { store, status } ) {
	return (
		<>
			<Section
				title={ __( 'New Administrator Alert', 'lw-firewall' ) }
				description={ __(
					'Send an email whenever an account gains administrator privileges, or an existing administrator account is modified — no matter how it happened: the admin screens, a plugin, the REST API, WP-CLI, or a direct write into the database.',
					'lw-firewall'
				) }
			>
				<SwitchRow
					title={ __( 'Enable Alerts', 'lw-firewall' ) }
					help={ __(
						'Works independently of the main firewall switch.',
						'lw-firewall'
					) }
					store={ store }
					name="admin_alert_enabled"
					onText={ __(
						'Email me when a new administrator appears',
						'lw-firewall'
					) }
					offText={ __( 'Off', 'lw-firewall' ) }
				/>
				<TextRow
					title={ __( 'Notification Email', 'lw-firewall' ) }
					help={ __(
						'Separate multiple addresses with commas. Leave empty to use the site admin email.',
						'lw-firewall'
					) }
					store={ store }
					name="admin_alert_email"
					placeholder={ store.data.meta.adminEmail }
				/>
				<SwitchRow
					title={ __( 'Account Takeover', 'lw-firewall' ) }
					help={ __(
						"Watches the username, email address and password of every administrator. Rewriting an admin's email address is how an account is seized — it hands over the password reset flow while the user ID stays the same, so watching for new accounts alone would never see it.",
						'lw-firewall'
					) }
					store={ store }
					name="admin_alert_changes"
					onText={ __(
						'Also alert when an existing administrator is modified',
						'lw-firewall'
					) }
					offText={ __( 'Off', 'lw-firewall' ) }
				/>
				<SwitchRow
					title={ __( 'Database Scan', 'lw-firewall' ) }
					help={ __(
						'Compares the live administrator list against a stored snapshot. This is what catches accounts inserted straight into the database, created by code that bypasses the WordPress user API, or added while this plugin was inactive.',
						'lw-firewall'
					) }
					store={ store }
					name="admin_alert_scan_enabled"
					onText={ __(
						'Hourly scan for administrators created outside WordPress',
						'lw-firewall'
					) }
					offText={ __( 'Off', 'lw-firewall' ) }
				/>
				<AlertActions store={ store } onDone={ status.reload } />
			</Section>
			<AlertStatus status={ status } />
			<Section title={ __( 'How detection works', 'lw-firewall' ) }>
				<KeyValue rows={ detection() } />
			</Section>
		</>
	);
}
