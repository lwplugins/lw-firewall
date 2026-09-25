/**
 * WordPress dependencies
 */
import { Button, TextControl } from '@wordpress/components';
import { useDispatch } from '@wordpress/data';
import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { store as noticesStore } from '@wordpress/notices';

/**
 * Internal dependencies
 */
import ResultBox from '../../components/ResultBox';
import { api, errorMessage } from '../../data/api';

/**
 * "Ban an address": IP (or IPv6, banned as its /64) + optional duration.
 * An empty duration uses the Auto-Ban duration. Whitelisted addresses and
 * storage failures come back as 409 with a message, shown as is.
 *
 * @param {Object}   props
 * @param {Array}    props.range    [ min, max ] seconds (auto_ban_duration).
 * @param {number}   props.fallback Default duration shown as placeholder.
 * @param {Function} props.onBanned Receives the fresh bans payload.
 */
export default function BanForm( { range, fallback, onBanned } ) {
	const [ ip, setIp ] = useState( '' );
	const [ duration, setDuration ] = useState( '' );
	const [ busy, setBusy ] = useState( false );
	const [ error, setError ] = useState( '' );
	const { createSuccessNotice } = useDispatch( noticesStore );
	const [ min = 60, max = 2592000 ] = range;

	const submit = async ( event ) => {
		event.preventDefault();
		setBusy( true );
		setError( '' );
		try {
			const r = await api.ban( ip.trim(), duration );
			if ( r.ok ) {
				createSuccessNotice(
					r.message ||
						sprintf(
							/* translators: %s: IP address. */
							__( '%s banned.', 'lw-firewall' ),
							r.ip
						),
					{ type: 'snackbar' }
				);
				setIp( '' );
				setDuration( '' );
			} else {
				setError( r.message );
			}
			if ( r.bans ) {
				onBanned( r.bans );
			}
		} catch ( e ) {
			setError( errorMessage( e ) );
		}
		setBusy( false );
	};

	return (
		<form className="lw-admin-banform" onSubmit={ submit }>
			<TextControl
				__next40pxDefaultSize
				__nextHasNoMarginBottom
				label={ __( 'IP address', 'lw-firewall' ) }
				className="lw-admin-mono"
				placeholder="203.0.113.7"
				value={ ip }
				onChange={ setIp }
				required
			/>
			<TextControl
				__next40pxDefaultSize
				__nextHasNoMarginBottom
				label={ __( 'Duration (seconds)', 'lw-firewall' ) }
				type="number"
				min={ min }
				max={ max }
				step={ 1 }
				placeholder={ String( fallback || '' ) }
				value={ duration }
				onChange={ setDuration }
			/>
			<Button
				__next40pxDefaultSize
				variant="secondary"
				type="submit"
				isBusy={ busy }
				disabled={ busy || ! ip.trim() }
				accessibleWhenDisabled
			>
				{ __( 'Ban address', 'lw-firewall' ) }
			</Button>
			{ error && <ResultBox tone="error" message={ error } /> }
		</form>
	);
}
