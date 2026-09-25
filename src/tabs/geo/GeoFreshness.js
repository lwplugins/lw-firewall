/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Per-country list freshness (GET /admin/status → geo.countries). A stale
 * country has no list younger than 7 days, so CIDR matching lets its
 * visitors through until the list is downloaded.
 *
 * @param {Object} props
 * @param {Object} props.status Status remote.
 * @param {Object} props.names  { CC: name }.
 */
export default function GeoFreshness( { status, names } ) {
	const countries = status.data?.geo.countries || [];
	if ( ! countries.length ) {
		return null;
	}
	return (
		<ul
			className="lw-geo-fresh"
			aria-label={ __( 'List freshness', 'lw-firewall' ) }
		>
			{ countries.map( ( c ) => (
				<li
					key={ c.cc }
					className={ `lw-chip ${ c.stale ? 'is-unknown' : 'is-ok' }` }
					title={ names[ c.cc ] || c.cc }
				>
					<code>{ c.cc }</code>
					<span>
						{ c.stale
							? __( 'Stale', 'lw-firewall' )
							: __( 'Current', 'lw-firewall' ) }
					</span>
					<span className="screen-reader-text">
						{ names[ c.cc ] || c.cc }
					</span>
				</li>
			) ) }
		</ul>
	);
}
