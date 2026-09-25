/**
 * WordPress dependencies
 */
import { __, _n, sprintf } from '@wordpress/i18n';
import { Icon, caution } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import StatusBadge from '../components/StatusBadge';
import { tabOfField } from './tabs';

/**
 * Nav extras: the Status warnings count, and a flag on every tab holding a
 * field the last save rejected.
 *
 * @param {Object}      errors Field errors { key: [ messages ] }.
 * @param {Object|null} status Status report.
 * @return {Object} { tabId: node }.
 */
export default function navMeta( errors, status ) {
	const meta = {};

	Object.keys( errors ).forEach( ( key ) => {
		const tab = tabOfField( key );
		if ( tab ) {
			meta[ tab ] = (
				<span className="lw-admin-navflag">
					<Icon icon={ caution } size={ 18 } />
					<span className="screen-reader-text">
						{ __( 'Has invalid fields', 'lw-firewall' ) }
					</span>
				</span>
			);
		}
	} );

	const warnings = status?.warnings || [];
	if ( warnings.length ) {
		const critical = warnings.some( ( w ) =>
			[ 'error', 'critical' ].includes( w.severity )
		);
		meta.status = (
			<StatusBadge status={ critical ? 'critical' : 'warning' }>
				<span aria-hidden="true">{ String( warnings.length ) }</span>
				<span className="screen-reader-text">
					{ sprintf(
						/* translators: %d: number of status warnings. */
						_n(
							'%d warning',
							'%d warnings',
							warnings.length,
							'lw-firewall'
						),
						warnings.length
					) }
				</span>
			</StatusBadge>
		);
	}

	return meta;
}
