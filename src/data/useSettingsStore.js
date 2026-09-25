/**
 * WordPress dependencies
 */
import { useDispatch } from '@wordpress/data';
import { useCallback, useEffect, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { store as noticesStore } from '@wordpress/notices';

/**
 * Internal dependencies
 */
import { api, errorMessage, fieldErrors } from './api';

const same = ( a, b ) => JSON.stringify( a ) === JSON.stringify( b );

/**
 * The lw_firewall options draft. Save sends only changed keys, never a key
 * pinned in wp-config.php (meta.locked). A `400 lw_firewall_invalid` keeps
 * the draft and puts `data.fields` next to each field; the server saves
 * nothing in that case (atomic save), so the draft stays dirty.
 *
 * @return {Object} Store: data { options, meta }, set, hasEdits, save, discard…
 */
export default function useSettingsStore() {
	const [ server, setServer ] = useState( null );
	const [ options, setOptions ] = useState( null );
	const [ error, setError ] = useState( null );
	const [ errors, setErrors ] = useState( {} );
	const [ isSaving, setIsSaving ] = useState( false );
	const { createSuccessNotice, createErrorNotice } =
		useDispatch( noticesStore );

	const apply = useCallback( ( data ) => {
		setServer( data );
		setOptions( data.options );
		setErrors( {} );
	}, [] );

	const reload = useCallback( () => {
		setError( null );
		return api
			.settings()
			.then( apply, ( e ) => setError( errorMessage( e ) ) );
	}, [ apply ] );

	useEffect( () => {
		reload();
	}, [ reload ] );

	const locked = server?.meta.locked || [];
	const patch = options
		? Object.fromEntries(
				Object.keys( options )
					.filter(
						( key ) =>
							! locked.includes( key ) &&
							! same( options[ key ], server.options[ key ] )
					)
					.map( ( key ) => [ key, options[ key ] ] )
			)
		: {};
	const hasEdits = Object.keys( patch ).length > 0;

	const set = ( key, value ) => {
		setOptions( ( prev ) => ( { ...prev, [ key ]: value } ) );
		if ( errors[ key ] ) {
			setErrors( ( prev ) => {
				const next = { ...prev };
				delete next[ key ];
				return next;
			} );
		}
	};

	const save = async () => {
		if ( ! hasEdits ) {
			return;
		}
		setIsSaving( true );
		try {
			apply( await api.saveSettings( patch ) );
			createSuccessNotice( __( 'Settings saved.', 'lw-firewall' ), {
				type: 'snackbar',
			} );
		} catch ( e ) {
			const fields = fieldErrors( e );
			if ( fields ) {
				setErrors( fields );
			}
			createErrorNotice(
				fields
					? __(
							'Nothing was saved. Fix the highlighted fields and save again.',
							'lw-firewall'
						)
					: errorMessage( e ),
				{ type: 'snackbar' }
			);
		}
		setIsSaving( false );
	};

	return {
		data: options ? { options, meta: server.meta } : null,
		saved: server?.options || {},
		isLoading: ! options && ! error,
		error,
		reload,
		apply,
		isLocked: ( key ) => locked.includes( key ),
		isDirty: ( key ) => key in patch,
		errors,
		set,
		hasEdits,
		isSaving,
		discard: () => {
			setOptions( server.options );
			setErrors( {} );
		},
		save,
	};
}
