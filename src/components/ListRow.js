/**
 * WordPress dependencies
 */
import { TextareaControl } from '@wordpress/components';
import { useEffect, useState } from '@wordpress/element';
import { _n, sprintf } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { fieldOf } from './Fields';
import SettingRow from './SettingRow';

/**
 * Textarea lines → list entries: trimmed, blanks dropped. A literal "0" is a
 * value like any other (the classic parser silently dropped it).
 *
 * @param {string} text Textarea value.
 * @return {string[]} Entries.
 */
export const toLines = ( text ) =>
	text
		.split( '\n' )
		.map( ( line ) => line.trim() )
		.filter( ( line ) => line !== '' );

const toText = ( value ) =>
	Array.isArray( value ) ? value.join( '\n' ) : String( value ?? '' );

/**
 * One-entry-per-line list option (IPs, proxies, bots, filter params). The
 * textarea keeps what is typed (trailing newline, blank lines) while the
 * store gets the clean array; a Discard or server reply that changes the
 * array resets the text. Server messages for the key appear under it.
 *
 * @param {Object}  props
 * @param {string}  props.title       Title.
 * @param {Element} props.help        Help.
 * @param {Object}  props.store       Settings store.
 * @param {string}  props.name        Option key (array value).
 * @param {number}  props.rows        Textarea rows.
 * @param {string}  props.placeholder Placeholder.
 * @param {Element} props.actions     Extra controls under the textarea.
 */
export default function ListRow( {
	title,
	help,
	store,
	name,
	rows = 6,
	placeholder,
	actions,
} ) {
	const field = fieldOf( store, name );
	const value = store.data.options[ name ];
	const [ text, setText ] = useState( () => toText( value ) );

	useEffect( () => {
		const lines = Array.isArray( value ) ? value : [];
		if ( JSON.stringify( toLines( text ) ) !== JSON.stringify( lines ) ) {
			setText( toText( value ) );
		}
		// Only an outside change of the value resyncs the text.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [ value ] );

	const count = toLines( text ).length;

	return (
		<SettingRow title={ title } help={ help } stacked { ...field }>
			<TextareaControl
				__nextHasNoMarginBottom
				label={ title }
				hideLabelFromVision
				className="lw-admin-mono"
				rows={ rows }
				disabled={ !! field.locked }
				placeholder={ placeholder }
				value={ text }
				onChange={ ( next ) => {
					setText( next );
					store.set( name, toLines( next ) );
				} }
			/>
			<div className="lw-admin-inline lw-admin-listfoot">
				<span className="lw-admin-hint">
					{ sprintf(
						/* translators: %d: number of list entries. */
						_n( '%d entry', '%d entries', count, 'lw-firewall' ),
						count
					) }
				</span>
				{ actions }
			</div>
		</SettingRow>
	);
}
