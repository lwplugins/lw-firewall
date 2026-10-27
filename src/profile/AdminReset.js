/**
 * Another user's profile (user-edit.php): status and "Reset two-factor".
 */
/**
 * WordPress dependencies
 */
import { Notice } from '@wordpress/components';
import { useEffect, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { reset } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import ConfirmAction from './ConfirmAction';
import Loading from './Loading';
import Row from './Row';
import { api, errorText } from './api';

/**
 * @param {Object} props
 * @param {number} props.userId Edited user.
 */
export default function AdminReset( { userId } ) {
	const [ status, setStatus ] = useState( null );
	const [ error, setError ] = useState( '' );
	const [ done, setDone ] = useState( false );

	useEffect( () => {
		api.user( userId )
			.then( setStatus )
			.catch( ( e ) =>
				setError(
					errorText( e ) ||
						__(
							'Could not load the two-factor settings.',
							'lw-firewall'
						)
				)
			);
	}, [ userId ] );

	if ( error ) {
		return (
			<Notice status="error" isDismissible={ false }>
				{ error }
			</Notice>
		);
	}
	if ( ! status ) {
		return <Loading rows={ 1 } />;
	}

	const hasAny = status.totp || status.passkeys.length > 0;

	return (
		<Row title={ __( 'Two-factor', 'lw-firewall' ) }>
			{ done && (
				<Notice status="success" isDismissible={ false }>
					{ __(
						'Two-factor authentication was reset. The user signs in with the password until they set it up again.',
						'lw-firewall'
					) }
				</Notice>
			) }
			{ ! done && ! hasAny && (
				<p>
					{ __(
						'This user has not set up two-factor authentication.',
						'lw-firewall'
					) }
				</p>
			) }
			{ ! done && hasAny && (
				<>
					<p>
						{ __(
							'This user signs in with a second factor. Reset it when they lost their phone or passkey: every factor, recovery code and remembered device is removed.',
							'lw-firewall'
						) }
					</p>
					<ConfirmAction
						label={ __( 'Reset two-factor', 'lw-firewall' ) }
						icon={ reset }
						destructive
						allowCode={ false }
						prompt={ __(
							'Confirm it with your own password.',
							'lw-firewall'
						) }
						onConfirm={ async ( proof ) => {
							setStatus( await api.reset( userId, proof ) );
							setDone( true );
						} }
					/>
				</>
			) }
		</Row>
	);
}
