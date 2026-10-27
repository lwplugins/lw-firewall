/**
 * Re-authentication fields of a sensitive action: the current password, or
 * (when the account has an authenticator app) a fresh code from it.
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
 * @param {Object}   props
 * @param {boolean}  props.allowCode   Offer the authenticator code.
 * @param {string}   props.prompt      Explanation above the fields.
 * @param {string}   props.submitLabel Confirm button text.
 * @param {boolean}  props.destructive Red confirm button.
 * @param {boolean}  props.busy        Request running.
 * @param {string}   props.error       Error text.
 * @param {Function} props.onSubmit    ( proof ) => void.
 * @param {Function} props.onCancel    Close.
 */
export default function ProofForm( {
	allowCode,
	prompt,
	submitLabel,
	destructive = false,
	busy,
	error,
	onSubmit,
	onCancel,
} ) {
	const [ password, setPassword ] = useState( '' );
	const [ code, setCode ] = useState( '' );
	const ready = password !== '' || ( allowCode && code !== '' );

	const submit = () => {
		if ( ready && ! busy ) {
			onSubmit(
				password !== ''
					? { current_password: password }
					: { code: code.replace( /\s+/g, '' ) }
			);
		}
	};
	const onKeyDown = ( event ) => {
		if ( event.key === 'Enter' ) {
			event.preventDefault();
			submit();
		}
	};

	return (
		<div className="lwfw-2fa-proof">
			<p className="lwfw-2fa-proof__prompt">
				{ prompt ||
					( allowCode
						? __(
								'Confirm it with your password or a code from your authenticator app.',
								'lw-firewall'
							)
						: __(
								'Confirm it with your password.',
								'lw-firewall'
							) ) }
			</p>
			<div className="lwfw-2fa-proof__fields">
				<TextControl
					__next40pxDefaultSize
					__nextHasNoMarginBottom
					type="password"
					autoComplete="current-password"
					label={ __( 'Current password', 'lw-firewall' ) }
					value={ password }
					onChange={ setPassword }
					onKeyDown={ onKeyDown }
					disabled={ busy }
				/>
				{ allowCode && (
					<TextControl
						__next40pxDefaultSize
						__nextHasNoMarginBottom
						inputMode="numeric"
						autoComplete="one-time-code"
						maxLength={ 7 }
						label={ __( 'or authenticator code', 'lw-firewall' ) }
						value={ code }
						onChange={ setCode }
						onKeyDown={ onKeyDown }
						disabled={ busy || password !== '' }
					/>
				) }
			</div>
			{ error && (
				<Notice status="error" isDismissible={ false }>
					{ error }
				</Notice>
			) }
			<div className="lwfw-2fa-actions">
				<Button
					__next40pxDefaultSize
					variant="primary"
					isDestructive={ destructive }
					isBusy={ busy }
					disabled={ ! ready || busy }
					onClick={ submit }
				>
					{ submitLabel }
				</Button>
				<Button
					__next40pxDefaultSize
					variant="tertiary"
					onClick={ onCancel }
					disabled={ busy }
				>
					{ __( 'Cancel', 'lw-firewall' ) }
				</Button>
			</div>
		</div>
	);
}
