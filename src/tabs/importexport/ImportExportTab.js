/**
 * WordPress dependencies
 */
import {
	Button,
	// Core has no stable ConfirmDialog yet (same as the sibling LW admins).
	// eslint-disable-next-line @wordpress/no-unsafe-wp-apis
	__experimentalConfirmDialog as ConfirmDialog,
	FormFileUpload,
} from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { download, upload } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import ResultBox from '../../components/ResultBox';
import Section from '../../components/Section';
import { api, errorMessage } from '../../data/api';
import ImportReport from './ImportReport';

// The server accepts up to 256 KB (POST /admin/import).
const MAX_BYTES = 256 * 1024;

/**
 * Browser download of a text file through a Blob link.
 *
 * @param {string} text     Content.
 * @param {string} filename File name.
 */
function saveFile( text, filename ) {
	const url = URL.createObjectURL(
		new Blob( [ text ], { type: 'application/json' } )
	);
	const link = document.createElement( 'a' );
	link.href = url;
	link.download = filename;
	document.body.appendChild( link );
	link.click();
	link.remove();
	URL.revokeObjectURL( url );
}

/**
 * Export (stored values, never wp-config constants) and import (file read in
 * the browser, JSON sent to the server). Import is not atomic: valid keys are
 * applied, invalid / pinned / unknown keys are reported, keys missing from
 * the file keep their current values. Import asks first.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store.
 */
export default function ImportExportTab( { store } ) {
	const [ busy, setBusy ] = useState( '' );
	const [ pending, setPending ] = useState( null ); // { name, text }
	const [ outcome, setOutcome ] = useState( null );

	const exportSettings = async () => {
		setBusy( 'export' );
		try {
			const { json, filename } = await api.exportSettings();
			saveFile(
				typeof json === 'string'
					? json
					: JSON.stringify( json, null, 2 ),
				filename || 'lw-firewall-settings.json'
			);
		} catch ( e ) {
			setOutcome( { error: errorMessage( e ) } );
		}
		setBusy( '' );
	};

	const pick = async ( file ) => {
		if ( ! file ) {
			return;
		}
		setOutcome( null );
		if ( file.size > MAX_BYTES ) {
			setOutcome( {
				error: __(
					'The file is larger than 256 KB, the most an import accepts.',
					'lw-firewall'
				),
			} );
			return;
		}
		const text = await file.text();
		try {
			JSON.parse( text );
		} catch {
			setOutcome( {
				error: __(
					'The file does not contain valid JSON.',
					'lw-firewall'
				),
			} );
			return;
		}
		setPending( { name: file.name, text } );
	};

	const runImport = async () => {
		const { text } = pending;
		setPending( null );
		setBusy( 'import' );
		try {
			const result = await api.importSettings( text );
			if ( result.settings ) {
				store.apply( result.settings );
			} else {
				store.reload();
			}
			setOutcome( { report: result.report } );
		} catch ( e ) {
			// 400 lw_firewall_import_invalid: not a settings document.
			setOutcome( { error: errorMessage( e ) } );
		}
		setBusy( '' );
	};

	return (
		<>
			<Section
				title={ __( 'Export Settings', 'lw-firewall' ) }
				description={ __(
					'Download your current firewall settings as a JSON file. You can use this file to import settings on another site.',
					'lw-firewall'
				) }
				actions={
					<Button
						__next40pxDefaultSize
						variant="secondary"
						icon={ download }
						isBusy={ busy === 'export' }
						onClick={ exportSettings }
					>
						{ __( 'Export Settings', 'lw-firewall' ) }
					</Button>
				}
			/>
			<Section
				title={ __( 'Import Settings', 'lw-firewall' ) }
				description={ __(
					'Upload a previously exported JSON file. Valid settings in the file replace the current ones, invalid values are skipped and reported, and settings missing from the file keep their current values.',
					'lw-firewall'
				) }
				actions={
					<FormFileUpload
						accept=".json,application/json"
						onChange={ ( event ) => {
							pick( event.currentTarget.files?.[ 0 ] );
							event.currentTarget.value = '';
						} }
						render={ ( { openFileDialog } ) => (
							<Button
								__next40pxDefaultSize
								variant="secondary"
								icon={ upload }
								isBusy={ busy === 'import' }
								disabled={ !! busy }
								accessibleWhenDisabled
								onClick={ openFileDialog }
							>
								{ __( 'Import Settings', 'lw-firewall' ) }
							</Button>
						) }
					/>
				}
			>
				{ outcome?.error || outcome?.report ? (
					<>
						{ outcome?.error && (
							<ResultBox tone="error" message={ outcome.error } />
						) }
						{ outcome?.report && (
							<ResultBox
								tone={
									Object.keys( outcome.report.invalid ).length
										? 'warning'
										: 'ok'
								}
								message={
									Object.keys( outcome.report.invalid ).length
										? __(
												'Settings imported, but some values were rejected.',
												'lw-firewall'
											)
										: __(
												'Settings imported successfully.',
												'lw-firewall'
											)
								}
							>
								<ImportReport report={ outcome.report } />
							</ResultBox>
						) }
					</>
				) : null }
			</Section>
			<ConfirmDialog
				isOpen={ !! pending }
				confirmButtonText={ __( 'Import', 'lw-firewall' ) }
				onConfirm={ runImport }
				onCancel={ () => setPending( null ) }
			>
				<p>
					{ sprintf(
						/* translators: %s: file name. */
						__(
							'Import the settings from %s? Every valid setting in the file replaces the current value right away; invalid ones are skipped and listed afterwards.',
							'lw-firewall'
						),
						pending?.name || ''
					) }
				</p>
				{ store.hasEdits && (
					<p>
						<strong>
							{ __(
								'Your unsaved changes on the other tabs will be discarded.',
								'lw-firewall'
							) }
						</strong>
					</p>
				) }
			</ConfirmDialog>
		</>
	);
}
