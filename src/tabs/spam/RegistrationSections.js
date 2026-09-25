/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import Callout from '../../components/Callout';
import { NumberRow, SwitchRow } from '../../components/Fields';
import Section from '../../components/Section';

const OFF = () => __( 'Off', 'lw-firewall' );
const BAN_DURATION = () =>
	__( 'How long the ban lasts in seconds (3600 = 1 hour).', 'lw-firewall' );

/**
 * Registration protection + registration auto-ban.
 *
 * @param {Object}       props
 * @param {Object}       props.store            Settings store.
 * @param {boolean|null} props.registrationOpen WP "Anyone can register".
 */
export default function Registration( { store, registrationOpen } ) {
	return (
		<>
			<Section
				title={ __( 'Registration Protection', 'lw-firewall' ) }
				description={ __(
					'Block bot sign-ups on wp-login.php?action=register without a captcha. Active only when "Anyone can register" is enabled in Settings → General.',
					'lw-firewall'
				) }
			>
				{ registrationOpen === false && (
					<Callout>
						{ __(
							'"Anyone can register" is off on this site, so registration protection is idle until it is turned on.',
							'lw-firewall'
						) }
					</Callout>
				) }
				<SwitchRow
					title={ __(
						'Enable Registration Protection',
						'lw-firewall'
					) }
					help={ __(
						'Adds a signed proof-of-render token and honeypot to the registration form. Only active when "Anyone can register" is enabled.',
						'lw-firewall'
					) }
					store={ store }
					name="register_protect_enabled"
					onText={ __(
						'Block bot registrations on wp-login.php?action=register',
						'lw-firewall'
					) }
					offText={ OFF() }
				/>
				<SwitchRow
					title={ __( 'Honeypot', 'lw-firewall' ) }
					help={ __(
						'Catches generic bots that fill every field. Invisible to real users.',
						'lw-firewall'
					) }
					store={ store }
					name="register_honeypot"
					onText={ __(
						'Add a hidden honeypot field',
						'lw-firewall'
					) }
					offText={ OFF() }
				/>
				<SwitchRow
					title={ __( 'Single-Use Token', 'lw-firewall' ) }
					help={ __(
						'Stores used tokens in the firewall storage backend so each rendered form can register only once.',
						'lw-firewall'
					) }
					store={ store }
					name="register_single_use"
					onText={ __( 'Reject reused tokens', 'lw-firewall' ) }
					offText={ OFF() }
				/>
				<NumberRow
					title={ __( 'Minimum Fill Time', 'lw-firewall' ) }
					help={ __(
						'Reject submissions faster than this many seconds after the form loaded (catches instant bot POSTs).',
						'lw-firewall'
					) }
					store={ store }
					name="register_min_fill_time"
					seconds
				/>
				<NumberRow
					title={ __( 'Token Lifetime', 'lw-firewall' ) }
					help={ __(
						'How long a rendered form stays valid, in seconds (3600 = 1 hour).',
						'lw-firewall'
					) }
					store={ store }
					name="register_token_max_age"
					seconds
				/>
			</Section>
			<Section
				title={ __( 'Registration Auto-Ban', 'lw-firewall' ) }
				description={ __(
					'Ban IPs that repeatedly submit spam registrations. A banned IP is blocked from the whole site, not just the registration form.',
					'lw-firewall'
				) }
			>
				<NumberRow
					title={ __( 'Ban Threshold', 'lw-firewall' ) }
					help={ __(
						'Number of rejected registrations from one IP before it is banned.',
						'lw-firewall'
					) }
					store={ store }
					name="register_ban_threshold"
				/>
				<NumberRow
					title={ __( 'Ban Duration', 'lw-firewall' ) }
					help={ BAN_DURATION() }
					store={ store }
					name="register_ban_duration"
					seconds
				/>
			</Section>
		</>
	);
}
