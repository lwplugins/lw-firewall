/**
 * Passkey list with add (label + re-auth + browser ceremony) and remove.
 */
/**
 * WordPress dependencies
 */
import { Button, Notice, TextControl } from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { plus, trash } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import ConfirmAction from './ConfirmAction';
import ProofForm from './ProofForm';
import { api, errorText } from './api';
import { createPasskey, supported } from './webauthn';
import { ago, datetime } from '../data/format';

/**
 * Text of a failed ceremony.
 *
 * @param {Error} error Rejection.
 * @return {string} Text.
 */
const ceremonyError = ( error ) =>
	error && error.name === 'NotAllowedError'
		? __(
				'The passkey prompt was closed or timed out. Try again.',
				'lw-firewall'
			)
		: errorText( error ) ||
			__( 'The passkey could not be added. Try again.', 'lw-firewall' );

/**
 * @param {Object}   props
 * @param {Object[]} props.passkeys  { id, label, created_at, last_used_at }.
 * @param {boolean}  props.available Passkeys work on this site.
 * @param {?Object}  props.factors   Re-auth factors (see ProofForm); null = password.
 * @param {Function} props.onChange  ( recoveryCodes? ) => void after a change.
 */
export default function Passkeys( { passkeys, available, factors, onChange } ) {
	const [ label, setLabel ] = useState( '' );
	const [ adding, setAdding ] = useState( false );
	const [ busy, setBusy ] = useState( false );
	const [ error, setError ] = useState( '' );
	const canAdd = available && supported();

	const add = async ( proof ) => {
		setBusy( true );
		setError( '' );
		try {
			const { key, options } = await api.passkeyBegin( proof );
			const credential = await createPasskey( options );
			const out = await api.passkeyFinish( { key, credential, label } );
			setAdding( false );
			setLabel( '' );
			onChange( out.recovery_codes || [] );
		} catch ( e ) {
			setError( ceremonyError( e ) );
		}
		setBusy( false );
	};

	return (
		<div className="lwfw-2fa-passkeys">
			{ passkeys.length > 0 ? (
				<ul className="lwfw-2fa-passkeys__list">
					{ passkeys.map( ( key ) => (
						<li key={ key.id } className="lwfw-2fa-passkeys__item">
							<span className="lwfw-2fa-passkeys__meta">
								<strong>{ key.label }</strong>
								<span className="description">
									{ sprintf(
										/* translators: 1: date added, 2: relative time of last use */
										__(
											'Added %1$s · last used %2$s',
											'lw-firewall'
										),
										datetime( key.created_at ),
										key.last_used_at
											? ago( key.last_used_at )
											: __( 'never', 'lw-firewall' )
									) }
								</span>
							</span>
							<ConfirmAction
								label={ __( 'Remove', 'lw-firewall' ) }
								icon={ trash }
								destructive
								factors={ factors }
								onConfirm={ async ( proof ) => {
									await api.passkeyDelete( key.id, proof );
									onChange( [] );
								} }
							/>
						</li>
					) ) }
				</ul>
			) : (
				<p className="description">
					{ __( 'No passkeys yet.', 'lw-firewall' ) }
				</p>
			) }

			{ ! canAdd && (
				<p className="description">
					{ available
						? __(
								'This browser cannot create passkeys.',
								'lw-firewall'
							)
						: __(
								'Passkeys are not available on this site.',
								'lw-firewall'
							) }
				</p>
			) }

			{ canAdd && ! adding && (
				<div className="lwfw-2fa-passkeys__add">
					<TextControl
						__next40pxDefaultSize
						__nextHasNoMarginBottom
						label={ __( 'Passkey name', 'lw-firewall' ) }
						placeholder={ __( 'e.g. Work laptop', 'lw-firewall' ) }
						maxLength={ 60 }
						value={ label }
						onChange={ setLabel }
						onKeyDown={ ( event ) => {
							if ( event.key === 'Enter' ) {
								event.preventDefault();
								setAdding( true );
							}
						} }
					/>
					<Button
						__next40pxDefaultSize
						variant="secondary"
						icon={ plus }
						onClick={ () => setAdding( true ) }
					>
						{ __( 'Add passkey', 'lw-firewall' ) }
					</Button>
				</div>
			) }

			{ canAdd && adding && (
				<ProofForm
					factors={ factors }
					submitLabel={ __( 'Continue', 'lw-firewall' ) }
					busy={ busy }
					error={ error }
					onSubmit={ add }
					onCancel={ () => {
						setAdding( false );
						setError( '' );
					} }
				/>
			) }

			{ error && ! adding && (
				<Notice status="error" isDismissible={ false }>
					{ error }
				</Notice>
			) }
		</div>
	);
}
