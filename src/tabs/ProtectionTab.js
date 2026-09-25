/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { NumberRow, SwitchRow } from '../components/Fields';
import Section from '../components/Section';

const BAN_DURATION = () =>
	__( 'How long the ban lasts in seconds (3600 = 1 hour).', 'lw-firewall' );

/**
 * Per-username lockout (1.6.0). It counts failures over the IP login
 * detection window (login_lockout_window) and has its own lock duration.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store.
 */
function UsernameLockout( { store } ) {
	const has = ( key ) => key in store.data.options;
	if ( ! has( 'login_user_limit_enabled' ) ) {
		return null;
	}
	return (
		<>
			<SwitchRow
				title={ __( 'Username Lockout', 'lw-firewall' ) }
				help={ __(
					'Also counts failed logins per username, from every IP together, so an attacker rotating addresses is still stopped. A locked username cannot log in from anywhere until the lock expires; whitelisted IPs bypass it. Clear a lock from the Automatic Bans list on the IP Rules tab or with WP-CLI.',
					'lw-firewall'
				) }
				store={ store }
				name="login_user_limit_enabled"
				onText={ __(
					'Lock usernames after repeated failed logins',
					'lw-firewall'
				) }
				offText={ __( 'Off', 'lw-firewall' ) }
			/>
			{ has( 'login_user_max_attempts' ) && (
				<NumberRow
					title={ __(
						'Failed Attempts per Username',
						'lw-firewall'
					) }
					help={ __(
						'Number of failed logins for one username, from any IP, within the detection window above before that username is locked.',
						'lw-firewall'
					) }
					store={ store }
					name="login_user_max_attempts"
				/>
			) }
			{ has( 'login_user_lockout_duration' ) && (
				<NumberRow
					title={ __( 'Username Lock Duration', 'lw-firewall' ) }
					help={ __(
						'How long the username stays locked, in seconds (900 = 15 minutes).',
						'lw-firewall'
					) }
					store={ store }
					name="login_user_lockout_duration"
					seconds
				/>
			) }
		</>
	);
}

export default function ProtectionTab( { store } ) {
	const endpoint = ( name, title, help ) => (
		<SwitchRow
			key={ name }
			title={ title }
			help={ help }
			store={ store }
			name={ name }
		/>
	);

	return (
		<>
			<Section
				title={ __( 'Endpoint Protection', 'lw-firewall' ) }
				description={ __(
					'Enable rate limiting on specific WordPress endpoints.',
					'lw-firewall'
				) }
			>
				{ endpoint(
					'protect_cron',
					__( 'Rate-limit wp-cron.php requests', 'lw-firewall' ),
					__(
						'Protects against DDoS attacks targeting wp-cron.php.',
						'lw-firewall'
					)
				) }
				{ endpoint(
					'protect_xmlrpc',
					__( 'Rate-limit xmlrpc.php requests', 'lw-firewall' ),
					__(
						'Protects against brute-force and DDoS via xmlrpc.php.',
						'lw-firewall'
					)
				) }
				{ endpoint(
					'protect_login',
					__( 'Rate-limit wp-login.php requests', 'lw-firewall' ),
					__(
						'Rate-limits wp-login.php requests per IP.',
						'lw-firewall'
					)
				) }
				{ endpoint(
					'protect_rest_api',
					__( 'Rate-limit REST API requests', 'lw-firewall' ),
					__(
						'Rate-limits /wp-json/ requests per IP.',
						'lw-firewall'
					)
				) }
				{ endpoint(
					'protect_404',
					__( 'Block 404 flood', 'lw-firewall' ),
					__(
						'Blocks IPs that generate excessive 404 errors (vulnerability scanning).',
						'lw-firewall'
					)
				) }
			</Section>

			<Section
				title={ __( 'Brute-Force Login Protection', 'lw-firewall' ) }
				description={ __(
					'Ban IPs that submit too many failed login attempts (fail2ban style). A banned IP is blocked from the whole site, not just wp-login.php.',
					'lw-firewall'
				) }
			>
				<SwitchRow
					title={ __( 'Enable Login Protection', 'lw-firewall' ) }
					help={ __(
						'Counts failed password attempts per IP via wp_login_failed.',
						'lw-firewall'
					) }
					store={ store }
					name="login_limit_enabled"
					onText={ __(
						'Ban IPs after repeated failed logins',
						'lw-firewall'
					) }
					offText={ __( 'Off', 'lw-firewall' ) }
				/>
				<NumberRow
					title={ __( 'Failed Attempts', 'lw-firewall' ) }
					help={ __(
						'Number of failed login attempts before the IP is banned.',
						'lw-firewall'
					) }
					store={ store }
					name="login_max_attempts"
				/>
				<NumberRow
					title={ __( 'Detection Window', 'lw-firewall' ) }
					help={ __(
						'Seconds within which failed attempts are counted (600 = 10 minutes).',
						'lw-firewall'
					) }
					store={ store }
					name="login_lockout_window"
					seconds
				/>
				<NumberRow
					title={ __( 'Ban Duration', 'lw-firewall' ) }
					help={ BAN_DURATION() }
					store={ store }
					name="login_lockout_duration"
					seconds
				/>
				<UsernameLockout store={ store } />
			</Section>

			<Section
				title={ __( 'Auto-Ban', 'lw-firewall' ) }
				description={ __(
					'Automatically ban IPs that repeatedly exceed rate limits.',
					'lw-firewall'
				) }
			>
				<SwitchRow
					title={ __( 'Enable Auto-Ban', 'lw-firewall' ) }
					help={ __(
						'After the threshold is reached, the IP is banned for the configured duration.',
						'lw-firewall'
					) }
					store={ store }
					name="auto_ban_enabled"
					onText={ __(
						'Ban IPs after repeated violations',
						'lw-firewall'
					) }
					offText={ __( 'Off', 'lw-firewall' ) }
				/>
				<NumberRow
					title={ __( 'Ban Threshold', 'lw-firewall' ) }
					help={ __(
						'Number of rate-limit violations before an IP is banned.',
						'lw-firewall'
					) }
					store={ store }
					name="auto_ban_threshold"
				/>
				<NumberRow
					title={ __( 'Ban Duration', 'lw-firewall' ) }
					help={ BAN_DURATION() }
					store={ store }
					name="auto_ban_duration"
					seconds
				/>
			</Section>
		</>
	);
}
