/**
 * WordPress dependencies
 */
import { Button, CheckboxControl, SearchControl } from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { closeSmall } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import { fieldOf } from './Fields';
import SettingRow from './SettingRow';

const normalize = ( text ) =>
	text.normalize( 'NFD' ).replace( /[̀-ͯ]/g, '' ).toLowerCase();

/**
 * Searchable country multi-select (meta.countries: [ { code, name } ]).
 * Selected countries show as removable chips; a stored code that is not in
 * the list (legacy input) stays visible, flagged, so it can be removed.
 *
 * @param {Object} props
 * @param {string} props.title Title.
 * @param {string} props.help  Help.
 * @param {Object} props.store Settings store.
 * @param {string} props.name  Option key (array of ISO-2 codes).
 */
export default function CountryPicker( { title, help, store, name } ) {
	const field = fieldOf( store, name );
	const countries = store.data.meta.countries;
	const selected = store.data.options[ name ] || [];
	const [ query, setQuery ] = useState( '' );
	const byCode = Object.fromEntries(
		countries.map( ( c ) => [ c.code, c.name ] )
	);
	const needle = normalize( query.trim() );
	const matches = needle
		? countries.filter(
				( c ) =>
					normalize( c.name ).includes( needle ) ||
					c.code.toLowerCase() === needle
			)
		: countries;

	const toggle = ( code, on ) =>
		store.set(
			name,
			on
				? [ ...selected, code ]
				: selected.filter( ( item ) => item !== code )
		);

	return (
		<SettingRow title={ title } help={ help } stacked { ...field }>
			<div className="lw-countries">
				<div className="lw-countries__chips" aria-live="polite">
					{ selected.length === 0 && (
						<span className="lw-admin-hint">
							{ __( 'No country selected.', 'lw-firewall' ) }
						</span>
					) }
					{ selected.map( ( code ) => (
						<span
							key={ code }
							className={ `lw-chip ${
								byCode[ code ] ? '' : 'is-unknown'
							}` }
							title={
								byCode[ code ]
									? undefined
									: __(
											'Not an ISO 3166–1 alpha-2 country code.',
											'lw-firewall'
										)
							}
						>
							<code>{ code }</code>
							<span>{ byCode[ code ] || '?' }</span>
							<Button
								size="small"
								icon={ closeSmall }
								disabled={ !! field.locked }
								label={ sprintf(
									/* translators: %s: country name or code. */
									__( 'Remove %s', 'lw-firewall' ),
									byCode[ code ] || code
								) }
								onClick={ () => toggle( code, false ) }
							/>
						</span>
					) ) }
				</div>
				<SearchControl
					__nextHasNoMarginBottom
					label={ __( 'Search countries', 'lw-firewall' ) }
					placeholder={ __(
						'Search a country or code…',
						'lw-firewall'
					) }
					value={ query }
					onChange={ setQuery }
					disabled={ !! field.locked }
				/>
				<div
					className="lw-countries__list"
					role="group"
					aria-label={ title }
				>
					{ matches.map( ( c ) => (
						<CheckboxControl
							key={ c.code }
							__nextHasNoMarginBottom
							label={ `${ c.name } (${ c.code })` }
							checked={ selected.includes( c.code ) }
							disabled={ !! field.locked }
							onChange={ ( on ) => toggle( c.code, on ) }
						/>
					) ) }
					{ matches.length === 0 && (
						<p className="lw-admin-hint">
							{ __(
								'No country matches that search.',
								'lw-firewall'
							) }
						</p>
					) }
				</div>
				<span className="lw-admin-hint">
					{ sprintf(
						/* translators: %d: number of blocked countries. */
						_n(
							'%d country blocked',
							'%d countries blocked',
							selected.length,
							'lw-firewall'
						),
						selected.length
					) }
				</span>
			</div>
		</SettingRow>
	);
}
