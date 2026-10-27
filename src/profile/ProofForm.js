/**
 * Re-authentication fields of a sensitive action.
 *
 * An account without a second factor confirms with its current password.
 * Once it has one, only a factor counts (the server refuses the password
 * then): a code from the authenticator app, one of its passkeys or an
 * unused recovery code.
 *
 * Lives inside the core profile <form>: no field has a name (nothing is
 * posted with the profile), and Enter runs this action instead of saving
 * the profile.
 */
/**
 * WordPress dependencies
 */
import { Button, Notice, TextControl } from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { api, errorText } from './api';
import { getPasskey, supported } from './webauthn';

/**
 * Methods the account can confirm with, in the order offered.
 *
 * @param {Object|null} factors { totp, recovery, passkey } or null (password).
 * @return {string[]} Method ids.
 */
const methodsOf = ( factors ) => {
	if ( ! factors ) {
		return [ 'password' ];
	}
	return [
		factors.totp && 'totp',
		factors.passkey && supported() && 'passkey',
		factors.recovery && 'recovery',
	].filter( Boolean );
};

const LABELS = {
	totp: () => __( 'Authenticator code', 'lw-firewall' ),
	passkey: () => __( 'Passkey', 'lw-firewall' ),
	recovery: () => __( 'Recovery code', 'lw-firewall' ),
};

/**
 * Text of a failed passkey prompt.
 *
 * @param {Error} error Rejection.
 * @return {string} Text.
 */
const passkeyError = ( error ) =>
	error && error.name === 'NotAllowedError'
		? __(
				'The passkey prompt was closed or timed out. Try again.',
				'lw-firewall'
			)
		: errorText( error ) ||
			__( 'The passkey was not accepted. Try again.', 'lw-firewall' );

/**
 * Shown when no method works in this browser.
 *
 * @param {Object}   props
 * @param {Function} props.onCancel Close.
 */
function NoMethod( { onCancel } ) {
	return (
		<div className="lwfw-2fa-proof">
			<Notice status="warning" isDismissible={ false }>
				{ __(
					'This browser cannot use your passkey and you have no recovery code left. Use another browser, or ask an administrator to reset two-factor for you.',
					'lw-firewall'
				) }
			</Notice>
			<div className="lwfw-2fa-actions">
				<Button
					__next40pxDefaultSize
					variant="tertiary"
					onClick={ onCancel }
				>
					{ __( 'Cancel', 'lw-firewall' ) }
				</Button>
			</div>
		</div>
	);
}

/**
 * @param {Object}      props
 * @param {Object|null} props.factors     Usable factors { totp, recovery, passkey }; null = password.
 * @param {string}      props.prompt      Explanation above the fields.
 * @param {string}      props.submitLabel Confirm button text.
 * @param {boolean}     props.destructive Red confirm button.
 * @param {boolean}     props.busy        Request running.
 * @param {string}      props.error       Error text.
 * @param {Function}    props.onSubmit    ( proof ) => void.
 * @param {Function}    props.onCancel    Close.
 */
export default function ProofForm( {
	factors,
	prompt,
	submitLabel,
	destructive = false,
	busy,
	error,
	onSubmit,
	onCancel,
} ) {
	const methods = methodsOf( factors );
	const [ method, setMethod ] = useState( methods[ 0 ] || '' );
	const [ value, setValue ] = useState( '' );
	const [ asking, setAsking ] = useState( false );
	const [ ceremonyError, setCeremonyError ] = useState( '' );
	const working = busy || asking;
	const ready = method === 'passkey' || value.trim() !== '';

	if ( ! methods.length ) {
		return <NoMethod onCancel={ onCancel } />;
	}

	const askPasskey = async () => {
		setAsking( true );
		setCeremonyError( '' );
		let proof = null;
		try {
			const { key, options } = await api.reauthPasskeyOptions();
			proof = { passkey_key: key, passkey: await getPasskey( options ) };
		} catch ( e ) {
			setCeremonyError( passkeyError( e ) );
		}
		setAsking( false );
		if ( proof ) {
			onSubmit( proof );
		}
	};

	const submit = () => {
		if ( ! ready || working ) {
			return;
		}
		if ( method === 'passkey' ) {
			askPasskey();
			return;
		}
		const fields = {
			password: { current_password: value },
			totp: { code: value.replace( /\s+/g, '' ) },
			recovery: { recovery_code: value.trim() },
		};
		onSubmit( fields[ method ] );
	};
	const onKeyDown = ( event ) => {
		if ( event.key === 'Enter' ) {
			event.preventDefault();
			submit();
		}
	};
	const choose = ( next ) => {
		setMethod( next );
		setValue( '' );
		setCeremonyError( '' );
	};

	const defaultPrompt = factors
		? __(
				'Confirm it with your second factor: a code from your authenticator app, your passkey or a recovery code.',
				'lw-firewall'
			)
		: __( 'Confirm it with your password.', 'lw-firewall' );
	const shown = error || ceremonyError;
	const isCode = method === 'totp' || method === 'recovery';

	return (
		<div className="lwfw-2fa-proof">
			<p className="lwfw-2fa-proof__prompt">
				{ prompt || defaultPrompt }
			</p>
			{ methods.length > 1 && (
				<div
					className="lwfw-2fa-proof__methods"
					role="group"
					aria-label={ __( 'Confirm with', 'lw-firewall' ) }
				>
					{ methods.map( ( id ) => (
						<Button
							key={ id }
							__next40pxDefaultSize
							variant="tertiary"
							isPressed={ method === id }
							disabled={ working }
							onClick={ () => choose( id ) }
						>
							{ LABELS[ id ]() }
						</Button>
					) ) }
				</div>
			) }
			{ method === 'password' && (
				<div className="lwfw-2fa-proof__fields">
					<TextControl
						__next40pxDefaultSize
						__nextHasNoMarginBottom
						type="password"
						autoComplete="current-password"
						label={ __( 'Current password', 'lw-firewall' ) }
						value={ value }
						onChange={ setValue }
						onKeyDown={ onKeyDown }
						disabled={ working }
					/>
				</div>
			) }
			{ isCode && (
				<div className="lwfw-2fa-proof__fields">
					<TextControl
						__next40pxDefaultSize
						__nextHasNoMarginBottom
						inputMode={ method === 'totp' ? 'numeric' : 'text' }
						autoComplete={
							method === 'totp' ? 'one-time-code' : 'off'
						}
						maxLength={ method === 'totp' ? 7 : 24 }
						label={ LABELS[ method ]() }
						value={ value }
						onChange={ setValue }
						onKeyDown={ onKeyDown }
						disabled={ working }
					/>
				</div>
			) }
			{ method === 'passkey' && (
				<p className="description">
					{ __(
						'Your browser asks for the passkey when you continue.',
						'lw-firewall'
					) }
				</p>
			) }
			{ shown && (
				<Notice status="error" isDismissible={ false }>
					{ shown }
				</Notice>
			) }
			<div className="lwfw-2fa-actions">
				<Button
					__next40pxDefaultSize
					variant="primary"
					isDestructive={ destructive }
					isBusy={ working }
					disabled={ ! ready || working }
					onClick={ submit }
				>
					{ submitLabel }
				</Button>
				<Button
					__next40pxDefaultSize
					variant="tertiary"
					onClick={ onCancel }
					disabled={ working }
				>
					{ __( 'Cancel', 'lw-firewall' ) }
				</Button>
			</div>
		</div>
	);
}
