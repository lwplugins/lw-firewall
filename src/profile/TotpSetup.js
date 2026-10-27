/**
 * Authenticator-app setup: current password → QR,
 * grouped key and otpauth link → code → recovery codes.
 */
/**
 * WordPress dependencies
 */
import { Button, Notice, TextControl } from '@wordpress/components';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import ProofForm from './ProofForm';
import { api, errorText } from './api';

const group = ( secret ) => ( secret.match( /.{1,4}/g ) || [] ).join( ' ' );

/**
 * QR code drawn by the shared qr entry (window.lwFirewallQr).
 *
 * @param {Object} props
 * @param {string} props.uri otpauth:// URI.
 */
function Qr( { uri } ) {
	const ref = useRef( null );
	useEffect( () => {
		if ( ref.current && window.lwFirewallQr ) {
			window.lwFirewallQr.render( ref.current, uri );
		}
	}, [ uri ] );

	return (
		<div
			ref={ ref }
			className="lwfw-2fa-qr"
			role="img"
			aria-label={ __(
				'QR code for your authenticator app',
				'lw-firewall'
			) }
		/>
	);
}

/**
 * @param {Object}   props
 * @param {?Object}  props.factors   Re-auth factors (see ProofForm); null = password.
 * @param {Function} props.onEnabled ( recoveryCodes ) => void.
 */
export default function TotpSetup( { factors, onEnabled } ) {
	const [ stage, setStage ] = useState( 'idle' );
	const [ setup, setSetup ] = useState( null );
	const [ code, setCode ] = useState( '' );
	const [ busy, setBusy ] = useState( false );
	const [ error, setError ] = useState( '' );

	const begin = async ( proof ) => {
		setBusy( true );
		setError( '' );
		try {
			setSetup( await api.totpBegin( proof ) );
			setStage( 'scan' );
		} catch ( e ) {
			setError( errorText( e ) );
		}
		setBusy( false );
	};

	const confirm = async () => {
		if ( busy || code.trim() === '' ) {
			return;
		}
		setBusy( true );
		setError( '' );
		try {
			const out = await api.totpConfirm( code.replace( /\s+/g, '' ) );
			setStage( 'idle' );
			setSetup( null );
			setCode( '' );
			onEnabled( out.recovery_codes || [] );
		} catch ( e ) {
			setError( errorText( e ) );
		}
		setBusy( false );
	};

	const cancel = () => {
		setStage( 'idle' );
		setSetup( null );
		setCode( '' );
		setError( '' );
	};

	if ( stage === 'proof' ) {
		return (
			<ProofForm
				factors={ factors }
				prompt={
					factors
						? ''
						: __(
								'Enter your current password to set up an authenticator app.',
								'lw-firewall'
							)
				}
				submitLabel={ __( 'Continue', 'lw-firewall' ) }
				busy={ busy }
				error={ error }
				onSubmit={ begin }
				onCancel={ cancel }
			/>
		);
	}

	if ( stage === 'scan' && setup ) {
		return (
			<div className="lwfw-2fa-setup">
				<p>
					{ __(
						'Scan the QR code with your authenticator app, or add the key by hand. Then enter the 6-digit code the app shows.',
						'lw-firewall'
					) }
				</p>
				<div className="lwfw-2fa-setup__grid">
					<Qr uri={ setup.uri } />
					<div className="lwfw-2fa-setup__key">
						<strong>{ __( 'Setup key', 'lw-firewall' ) }</strong>
						<code>{ group( setup.secret ) }</code>
						<a href={ setup.uri }>
							{ __(
								'Open in your authenticator app',
								'lw-firewall'
							) }
						</a>
						<span className="description">
							{ __(
								'This key is valid for 10 minutes.',
								'lw-firewall'
							) }
						</span>
					</div>
				</div>
				<TextControl
					__next40pxDefaultSize
					__nextHasNoMarginBottom
					className="lwfw-2fa-code"
					inputMode="numeric"
					autoComplete="one-time-code"
					maxLength={ 7 }
					label={ __(
						'Code from your authenticator app',
						'lw-firewall'
					) }
					value={ code }
					onChange={ setCode }
					onKeyDown={ ( event ) => {
						if ( event.key === 'Enter' ) {
							event.preventDefault();
							confirm();
						}
					} }
					disabled={ busy }
				/>
				{ error && (
					<Notice status="error" isDismissible={ false }>
						{ error }
					</Notice>
				) }
				<div className="lwfw-2fa-actions">
					<Button
						__next40pxDefaultSize
						variant="primary"
						isBusy={ busy }
						disabled={ busy || code.trim() === '' }
						onClick={ confirm }
					>
						{ __( 'Turn on', 'lw-firewall' ) }
					</Button>
					<Button
						__next40pxDefaultSize
						variant="tertiary"
						onClick={ cancel }
						disabled={ busy }
					>
						{ __( 'Cancel', 'lw-firewall' ) }
					</Button>
				</div>
			</div>
		);
	}

	return (
		<>
			{ error && (
				<Notice status="error" isDismissible={ false }>
					{ error }
				</Notice>
			) }
			<Button
				__next40pxDefaultSize
				variant="secondary"
				isBusy={ busy }
				disabled={ busy }
				onClick={ () => setStage( 'proof' ) }
			>
				{ __( 'Set up authenticator app', 'lw-firewall' ) }
			</Button>
		</>
	);
}
