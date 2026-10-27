/**
 * Freshly issued recovery codes: shown once, with copy and download.
 */
/**
 * WordPress dependencies
 */
import { Button } from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { check, copy, download } from '@wordpress/icons';

/**
 * Save the codes as a .txt file.
 *
 * @param {string[]} codes Codes.
 */
const downloadCodes = ( codes ) => {
	const host = window.location.hostname;
	const text = [
		/* translators: %s: site host name */
		sprintf( __( 'Recovery codes for %s', 'lw-firewall' ), host ),
		__( 'Each code signs you in once.', 'lw-firewall' ),
		'',
		...codes,
		'',
	].join( '\n' );
	const url = URL.createObjectURL(
		new window.Blob( [ text ], { type: 'text/plain' } )
	);
	const link = document.createElement( 'a' );
	link.href = url;
	link.download = `recovery-codes-${ host }.txt`;
	document.body.appendChild( link );
	link.click();
	link.remove();
	URL.revokeObjectURL( url );
};

/**
 * @param {Object}   props
 * @param {string[]} props.codes  Plain codes.
 * @param {Function} props.onDone Dismiss.
 */
export default function RecoveryCodes( { codes, onDone } ) {
	const [ copied, setCopied ] = useState( false );

	const copyCodes = async () => {
		try {
			await window.navigator.clipboard.writeText( codes.join( '\n' ) );
			setCopied( true );
		} catch {
			setCopied( false );
		}
	};

	return (
		<div className="lwfw-2fa-codes" role="region" aria-live="polite">
			<h3>{ __( 'Save your recovery codes', 'lw-firewall' ) }</h3>
			<p>
				{ __(
					'If you lose your phone or passkey, each of these codes signs you in once. Save them now: they are shown only this time.',
					'lw-firewall'
				) }
			</p>
			<ol className="lwfw-2fa-codes__list">
				{ codes.map( ( code ) => (
					<li key={ code }>
						<code>{ code }</code>
					</li>
				) ) }
			</ol>
			<div className="lwfw-2fa-actions">
				<Button
					__next40pxDefaultSize
					variant="secondary"
					icon={ copied ? check : copy }
					onClick={ copyCodes }
				>
					{ copied
						? __( 'Copied', 'lw-firewall' )
						: __( 'Copy', 'lw-firewall' ) }
				</Button>
				<Button
					__next40pxDefaultSize
					variant="secondary"
					icon={ download }
					onClick={ () => downloadCodes( codes ) }
				>
					{ __( 'Download', 'lw-firewall' ) }
				</Button>
				<Button
					__next40pxDefaultSize
					variant="primary"
					onClick={ onDone }
				>
					{ __( 'I saved them', 'lw-firewall' ) }
				</Button>
			</div>
		</div>
	);
}
