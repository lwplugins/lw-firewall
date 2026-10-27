/**
 * A button that opens the re-authentication fields and runs an action.
 */
/**
 * WordPress dependencies
 */
import { Button } from '@wordpress/components';
import { useState } from '@wordpress/element';

/**
 * Internal dependencies
 */
import ProofForm from './ProofForm';
import { errorText } from './api';

/**
 * @param {Object}   props
 * @param {string}   props.label       Button text.
 * @param {Object}   props.icon        Button icon.
 * @param {string}   props.confirm     Confirm button text (default: label).
 * @param {string}   props.prompt      Explanation above the fields.
 * @param {boolean}  props.allowCode   Offer the authenticator code.
 * @param {boolean}  props.destructive Red buttons.
 * @param {Function} props.onConfirm   ( proof ) => Promise.
 */
export default function ConfirmAction( {
	label,
	icon,
	confirm,
	prompt,
	allowCode,
	destructive = false,
	onConfirm,
} ) {
	const [ open, setOpen ] = useState( false );
	const [ busy, setBusy ] = useState( false );
	const [ error, setError ] = useState( '' );

	if ( ! open ) {
		return (
			<Button
				__next40pxDefaultSize
				variant="secondary"
				icon={ icon }
				isDestructive={ destructive }
				onClick={ () => setOpen( true ) }
			>
				{ label }
			</Button>
		);
	}

	const submit = async ( proof ) => {
		setBusy( true );
		setError( '' );
		try {
			await onConfirm( proof );
			setOpen( false );
		} catch ( e ) {
			setError( errorText( e ) );
		}
		setBusy( false );
	};

	return (
		<ProofForm
			allowCode={ allowCode }
			prompt={ prompt }
			submitLabel={ confirm || label }
			destructive={ destructive }
			busy={ busy }
			error={ error }
			onSubmit={ submit }
			onCancel={ () => {
				setOpen( false );
				setError( '' );
			} }
		/>
	);
}
