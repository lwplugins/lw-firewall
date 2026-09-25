/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { NumberRow, SwitchRow } from '../../components/Fields';
import Section from '../../components/Section';

const OFF = () => __( 'Off', 'lw-firewall' );
const BAN_DURATION = () =>
	__( 'How long the ban lasts in seconds (3600 = 1 hour).', 'lw-firewall' );

/**
 * Password reset flood limits.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store.
 */
export function ResetFlood( { store } ) {
	return (
		<Section
			title={ __( 'Password Reset Flood Protection', 'lw-firewall' ) }
			description={ __(
				"A reset flood has three shapes, and each needs its own limit: one IP hammering the form, many IPs targeting one person's inbox, and sheer volume burning your hosting mail quota.",
				'lw-firewall'
			) }
		>
			<SwitchRow
				title={ __( 'Enable Reset Protection', 'lw-firewall' ) }
				help={ __(
					'Covers wp-login.php?action=lostpassword and the WooCommerce "Lost your password?" form — both go through the same WordPress hook. Requests started by an administrator or by WP-CLI are never limited.',
					'lw-firewall'
				) }
				store={ store }
				name="reset_protect_enabled"
				onText={ __(
					'Rate limit password reset requests',
					'lw-firewall'
				) }
				offText={ OFF() }
			/>
			<NumberRow
				title={ __( 'Requests per IP', 'lw-firewall' ) }
				help={ __(
					'How many reset requests one IP address may make per window. 0 disables this limit.',
					'lw-firewall'
				) }
				store={ store }
				name="reset_ip_max"
			/>
			<NumberRow
				title={ __( 'Per-IP Window', 'lw-firewall' ) }
				help={ __(
					'Length of the per-IP window in seconds (900 = 15 minutes).',
					'lw-firewall'
				) }
				store={ store }
				name="reset_ip_window"
				seconds
			/>
			<NumberRow
				title={ __( 'Requests per Account', 'lw-firewall' ) }
				help={ __(
					"How many reset emails one account may receive per window, no matter how many different IPs ask. This is the only limit that stops a distributed flood of one person's inbox. 0 disables it.",
					'lw-firewall'
				) }
				store={ store }
				name="reset_user_max"
			/>
			<NumberRow
				title={ __( 'Per-Account Window', 'lw-firewall' ) }
				help={ __(
					'Length of the per-account window in seconds (3600 = 1 hour).',
					'lw-firewall'
				) }
				store={ store }
				name="reset_user_window"
				seconds
			/>
			<NumberRow
				title={ __( 'Site-Wide Hourly Cap', 'lw-firewall' ) }
				help={ __(
					'Total reset emails the site will send in an hour. Protects your hosting mail quota and stops your domain being flagged as a spam source. 0 disables it.',
					'lw-firewall'
				) }
				store={ store }
				name="reset_global_max"
			/>
		</Section>
	);
}

/**
 * Password reset hardening.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store.
 */
export function ResetHardening( { store } ) {
	return (
		<Section
			title={ __( 'Password Reset Hardening', 'lw-firewall' ) }
			description={ __(
				'Filter out direct bot POSTs, escalate repeat offenders to a site-wide ban, and optionally take administrator accounts out of the reset flow entirely.',
				'lw-firewall'
			) }
		>
			<SwitchRow
				title={ __( 'Proof of Render', 'lw-firewall' ) }
				help={ __(
					'Rejects direct POSTs that never loaded the form. Only enforced on wp-login.php, since other lost-password forms (WooCommerce, custom login pages) do not render the token. Turn this off if a login plugin replaces the wp-login form.',
					'lw-firewall'
				) }
				store={ store }
				name="reset_proof_enabled"
				onText={ __(
					'Require a signed token and honeypot on the wp-login form',
					'lw-firewall'
				) }
				offText={ OFF() }
			/>
			<NumberRow
				title={ __( 'Minimum Fill Time', 'lw-firewall' ) }
				help={ __(
					'Reject submissions faster than this many seconds after the form loaded. Separate from the registration setting, so the two forms can be tuned independently.',
					'lw-firewall'
				) }
				store={ store }
				name="reset_min_fill_time"
				seconds
			/>
			<NumberRow
				title={ __( 'Token Lifetime', 'lw-firewall' ) }
				help={ __(
					'How long a rendered lost-password form stays valid, in seconds (3600 = 1 hour).',
					'lw-firewall'
				) }
				store={ store }
				name="reset_token_max_age"
				seconds
			/>
			<SwitchRow
				title={ __( 'Single-Use Token', 'lw-firewall' ) }
				help={ __(
					'Each rendered form may submit one reset request. Without this, a bot can load the form once and replay that token for the whole token lifetime.',
					'lw-firewall'
				) }
				store={ store }
				name="reset_single_use"
				onText={ __( 'Reject reused tokens', 'lw-firewall' ) }
				offText={ OFF() }
			/>
			<SwitchRow
				title={ __( 'Auto-Ban', 'lw-firewall' ) }
				help={ __(
					'A banned IP is blocked from the whole site by the MU-plugin worker. Account and site-wide limits never ban: they say nothing about who happened to ask last.',
					'lw-firewall'
				) }
				store={ store }
				name="reset_auto_ban"
				onText={ __(
					'Ban IPs that trip the per-IP limit or fail the token check',
					'lw-firewall'
				) }
				offText={ OFF() }
			/>
			<NumberRow
				title={ __( 'Ban Duration', 'lw-firewall' ) }
				help={ BAN_DURATION() }
				store={ store }
				name="reset_ban_duration"
				seconds
			/>
			<SwitchRow
				title={ __( 'Email Alert', 'lw-firewall' ) }
				help={ __(
					'Sends at most one message per limit per hour, to the recipients configured on the Alerts tab.',
					'lw-firewall'
				) }
				store={ store }
				name="reset_alert_enabled"
				onText={ __(
					'Email me when a reset limit is reached',
					'lw-firewall'
				) }
				offText={ OFF() }
			/>
			<SwitchRow
				title={ __( 'Block Admin Resets', 'lw-firewall' ) }
				help={ __(
					'Closes the "flood the admin inbox, then phish the reset link" path entirely. A locked-out administrator can then only be recovered by WP-CLI or by another administrator, so leave this off unless you have that access.',
					'lw-firewall'
				) }
				store={ store }
				name="reset_block_admins"
				onText={ __(
					'Never allow password reset for administrator accounts',
					'lw-firewall'
				) }
				offText={ OFF() }
			/>
		</Section>
	);
}
