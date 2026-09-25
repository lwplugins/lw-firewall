/**
 * WordPress dependencies
 */
import { __, _n, sprintf } from '@wordpress/i18n';

const keys = ( list ) =>
	list.map( ( key, index ) => (
		<span key={ key }>
			{ index > 0 && ', ' }
			<code>{ key }</code>
		</span>
	) );

/**
 * Per-key import report (import is not atomic): imported keys, keys skipped
 * because a wp-config.php constant pins them, unknown keys, and every
 * rejected key with its messages. Keys missing from the file kept their
 * current values.
 *
 * @param {Object} props
 * @param {Object} props.report { imported, invalid, locked, unknown }.
 */
export default function ImportReport( { report } ) {
	const invalid = Object.entries( report.invalid );

	return (
		<div className="lw-admin-report">
			<p>
				{ sprintf(
					/* translators: %d: number of imported settings. */
					_n(
						'%d setting imported.',
						'%d settings imported.',
						report.imported.length,
						'lw-firewall'
					),
					report.imported.length
				) }{ ' ' }
				{ __(
					'Settings missing from the file kept their current values.',
					'lw-firewall'
				) }
			</p>
			{ report.imported.length > 0 && (
				<details>
					<summary>{ __( 'Imported keys', 'lw-firewall' ) }</summary>
					<p>{ keys( report.imported ) }</p>
				</details>
			) }
			{ report.locked.length > 0 && (
				<p>
					{ __( 'Skipped, pinned in wp-config.php:', 'lw-firewall' ) }{ ' ' }
					{ keys( report.locked ) }
				</p>
			) }
			{ report.unknown.length > 0 && (
				<p>
					{ __( 'Unknown keys ignored:', 'lw-firewall' ) }{ ' ' }
					{ keys( report.unknown ) }
				</p>
			) }
			{ invalid.length > 0 && (
				<>
					<p>
						{ sprintf(
							/* translators: %d: number of rejected settings. */
							_n(
								'%d value was invalid and not imported; that setting kept its current value:',
								'%d values were invalid and not imported; those settings kept their current values:',
								invalid.length,
								'lw-firewall'
							),
							invalid.length
						) }
					</p>
					<ul className="lw-admin-fielderror">
						{ invalid.map( ( [ key, messages ] ) => (
							<li key={ key }>
								<code>{ key }</code>{ ' ' }
								{ [].concat( messages ).join( ' ' ) }
							</li>
						) ) }
					</ul>
				</>
			) }
		</div>
	);
}
