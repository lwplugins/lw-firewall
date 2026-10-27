/**
 * WordPress dependencies
 */
import { ToggleControl } from '@wordpress/components';
import { useCallback } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import Callout from '../../components/Callout';
import { NumberRow, SwitchRow, fieldOf } from '../../components/Fields';
import Section from '../../components/Section';
import StatusBadge from '../../components/StatusBadge';
import { api } from '../../data/api';
import useRemote from '../../data/useRemote';
import AdoptionSection from './AdoptionSection';
import RolesRow from './RolesRow';

/**
 * Two-factor tab: the master switch in the card header, the policy, the
 * emergency exit and the adoption per role.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store.
 */
export default function TwoFactorTab( { store } ) {
	const load = useCallback( () => api.twoFactorSummary(), [] );
	const summary = useRemote( load );
	const field = fieldOf( store, 'twofa_enabled' );
	const on = !! store.data.options.twofa_enabled;

	const actions = (
		<div className="lw-admin-inline lw-fw-headers__switch">
			<StatusBadge status={ on ? 'ok' : 'idle' }>
				{ on ? __( 'On', 'lw-firewall' ) : __( 'Off', 'lw-firewall' ) }
			</StatusBadge>
			<ToggleControl
				__nextHasNoMarginBottom
				label={ __( 'Two-factor login', 'lw-firewall' ) }
				checked={ on }
				disabled={ !! field.locked }
				onChange={ ( value ) => store.set( 'twofa_enabled', value ) }
			/>
		</div>
	);

	return (
		<>
			<Section
				title={ __( 'Two-Factor Login', 'lw-firewall' ) }
				description={ __(
					'After the password, users confirm with an authenticator app, a recovery code or a passkey. Passkeys can also replace the password.',
					'lw-firewall'
				) }
				actions={ actions }
			>
				{ field.locked && (
					<p className="lw-fw-headers__locked">
						{ sprintf(
							/* translators: %s: PHP constant name. */
							__( 'Set in wp-config.php (%s).', 'lw-firewall' ),
							field.locked
						) }
					</p>
				) }
				<Callout>
					{ __(
						"Locked out? Add define( 'LW_FIREWALL_TWOFA_ENABLED', false ); to wp-config.php to switch two-factor login off at once, or remove one user's factors with wp lw-firewall 2fa reset <user>.",
						'lw-firewall'
					) }
				</Callout>
				<RolesRow store={ store } />
				<NumberRow
					title={ __( 'Grace Period', 'lw-firewall' ) }
					help={ __(
						'Days a required user can keep logging in with the password alone, with a reminder, before setup becomes mandatory.',
						'lw-firewall'
					) }
					store={ store }
					name="twofa_grace_days"
				/>
				<NumberRow
					title={ __( 'Remember This Device', 'lw-firewall' ) }
					help={ __(
						'Days a browser can skip the second step after a successful one. 0 = off, every login asks.',
						'lw-firewall'
					) }
					store={ store }
					name="twofa_remember_days"
				/>
				<SwitchRow
					title={ __( 'Passwordless Passkey Login', 'lw-firewall' ) }
					help={ __(
						'Show a passkey button on the login page. A passkey replaces both the password and the second step.',
						'lw-firewall'
					) }
					store={ store }
					name="twofa_passkey_login"
					onText={ __( 'Passkey button shown', 'lw-firewall' ) }
					offText={ __( 'Off', 'lw-firewall' ) }
				/>
				<SwitchRow
					title={ __( 'Block Application Passwords', 'lw-firewall' ) }
					help={ __(
						'Application passwords skip the second step. Turn this on to disable them for users who have a second factor.',
						'lw-firewall'
					) }
					store={ store }
					name="twofa_block_app_passwords"
					onText={ __( 'Disabled for these users', 'lw-firewall' ) }
					offText={ __( 'Allowed', 'lw-firewall' ) }
				/>
			</Section>
			<AdoptionSection summary={ summary } />
		</>
	);
}
