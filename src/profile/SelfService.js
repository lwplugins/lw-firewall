/**
 * The user's own two-factor settings (profile.php).
 */
/**
 * WordPress dependencies
 */
import { Icon, Notice } from '@wordpress/components';
import { useCallback, useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { backup, shield, trash } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import ConfirmAction from './ConfirmAction';
import Loading from './Loading';
import Passkeys from './Passkeys';
import RecoveryCodes from './RecoveryCodes';
import Row from './Row';
import TotpSetup from './TotpSetup';
import { api, errorText } from './api';
import { datetime } from '../data/format';

/**
 * Summary line of the current state.
 *
 * @param {Object} status /me response.
 * @return {string} Text.
 */
const summary = ( status ) => {
	const parts = [];
	if ( status.totp ) {
		parts.push( __( 'authenticator app', 'lw-firewall' ) );
	}
	if ( status.passkeys.length ) {
		parts.push(
			sprintf(
				/* translators: %d: number of passkeys */
				_n(
					'%d passkey',
					'%d passkeys',
					status.passkeys.length,
					'lw-firewall'
				),
				status.passkeys.length
			)
		);
	}
	return parts.length
		? sprintf(
				/* translators: %s: list of enabled factors */
				__( 'On: %s', 'lw-firewall' ),
				parts.join( ', ' )
			)
		: __( 'Off', 'lw-firewall' );
};

/**
 * @param {Object}  props
 * @param {boolean} props.passkeysAvailable WebAuthn works on this site.
 */
export default function SelfService( { passkeysAvailable } ) {
	const [ status, setStatus ] = useState( null );
	const [ loadError, setLoadError ] = useState( '' );
	const [ codes, setCodes ] = useState( [] );
	const [ notice, setNotice ] = useState( '' );

	const load = useCallback( async () => {
		try {
			setStatus( await api.me() );
			setLoadError( '' );
		} catch ( e ) {
			setLoadError(
				errorText( e ) ||
					__(
						'Could not load the two-factor settings.',
						'lw-firewall'
					)
			);
		}
	}, [] );

	useEffect( () => {
		load();
	}, [ load ] );

	const changed = ( newCodes = [] ) => {
		if ( newCodes.length ) {
			setCodes( newCodes );
		}
		setNotice( '' );
		return load();
	};

	if ( loadError ) {
		return (
			<Notice status="error" isDismissible={ false }>
				{ loadError }
			</Notice>
		);
	}
	if ( ! status ) {
		return <Loading />;
	}

	const hasAny = status.totp || status.passkeys.length > 0;

	return (
		<div className="lwfw-2fa-self">
			<p className={ `lwfw-2fa-state ${ hasAny ? 'is-on' : 'is-off' }` }>
				<Icon icon={ shield } size={ 24 } />
				<strong>{ summary( status ) }</strong>
			</p>
			{ status.required && ! hasAny && (
				<Notice status="warning" isDismissible={ false }>
					{ sprintf(
						/* translators: %s: date */
						__(
							'Your account must use two-factor authentication. Set it up before %s, or the next sign-in asks you to.',
							'lw-firewall'
						),
						datetime( status.grace_ends_at )
					) }
				</Notice>
			) }
			{ notice && (
				<Notice status="success" onRemove={ () => setNotice( '' ) }>
					{ notice }
				</Notice>
			) }
			{ codes.length > 0 && (
				<RecoveryCodes
					codes={ codes }
					onDone={ () => setCodes( [] ) }
				/>
			) }

			<Row title={ __( 'Authenticator app', 'lw-firewall' ) }>
				{ status.totp ? (
					<>
						<p>
							{ __(
								'Codes from your authenticator app are on.',
								'lw-firewall'
							) }
						</p>
						<ConfirmAction
							label={ __(
								'Remove authenticator app',
								'lw-firewall'
							) }
							icon={ trash }
							destructive
							allowCode
							onConfirm={ async ( proof ) => {
								await api.totpDelete( proof );
								await changed();
							} }
						/>
					</>
				) : (
					<TotpSetup needsProof={ hasAny } onEnabled={ changed } />
				) }
			</Row>

			<Row title={ __( 'Passkeys', 'lw-firewall' ) }>
				<Passkeys
					passkeys={ status.passkeys }
					available={ passkeysAvailable }
					hasTotp={ status.totp }
					onChange={ changed }
				/>
			</Row>

			{ hasAny && (
				<Row title={ __( 'Recovery codes', 'lw-firewall' ) }>
					<p>
						{ sprintf(
							/* translators: %d: number of unused recovery codes */
							_n(
								'%d unused code left.',
								'%d unused codes left.',
								status.recovery_left,
								'lw-firewall'
							),
							status.recovery_left
						) }
					</p>
					<ConfirmAction
						label={ __( 'Create new codes', 'lw-firewall' ) }
						icon={ backup }
						prompt={ __(
							'The old codes stop working. Confirm it with your password or a code from your authenticator app.',
							'lw-firewall'
						) }
						allowCode={ status.totp }
						onConfirm={ async ( proof ) => {
							const out = await api.regenerate( proof );
							await changed( out.recovery_codes || [] );
						} }
					/>
				</Row>
			) }

			{ hasAny && (
				<Row title={ __( 'Remembered devices', 'lw-firewall' ) }>
					<p>
						{ __(
							'Browsers where you ticked "remember this device" skip the second step for a while.',
							'lw-firewall'
						) }
					</p>
					<ConfirmAction
						label={ __(
							'Forget all remembered devices',
							'lw-firewall'
						) }
						allowCode={ status.totp }
						onConfirm={ async ( proof ) => {
							await api.forgetDevices( proof );
							setNotice(
								__(
									'Every remembered device asks for the second step again.',
									'lw-firewall'
								)
							);
						} }
					/>
				</Row>
			) }
		</div>
	);
}
