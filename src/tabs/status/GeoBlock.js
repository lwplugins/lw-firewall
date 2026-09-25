/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import KeyValue from '../../components/KeyValue';
import Section from '../../components/Section';
import StatusBadge from '../../components/StatusBadge';
import { datetime, until } from '../../data/format';
import yesNo from './yesNo';

/**
 * Geo blocking state: active or not, per-country list freshness, cache
 * directory and the .htaccess CF-IPCountry block.
 *
 * @param {Object} props
 * @param {Object} props.geo Status geo block.
 */
export default function GeoBlock( { geo } ) {
	return (
		<Section
			title={ __( 'Geo Blocking', 'lw-firewall' ) }
			badge={
				<StatusBadge status={ geo.active ? 'ok' : 'idle' }>
					{ geo.active
						? __( 'Active', 'lw-firewall' )
						: __( 'Inactive', 'lw-firewall' ) }
				</StatusBadge>
			}
		>
			<KeyValue
				rows={ [
					{
						label: __( 'Country lists', 'lw-firewall' ),
						help: __(
							'Stale: no list younger than 7 days, so CIDR matching lets those visitors through.',
							'lw-firewall'
						),
						value: geo.countries.length ? (
							<span className="lw-admin-inline">
								{ geo.countries.map( ( c ) => (
									<StatusBadge
										key={ c.cc }
										status={ c.stale ? 'warning' : 'ok' }
									>
										{ `${ c.cc } · ${
											c.stale
												? __( 'Stale', 'lw-firewall' )
												: __( 'Current', 'lw-firewall' )
										}` }
									</StatusBadge>
								) ) }
							</span>
						) : (
							__( 'No country selected.', 'lw-firewall' )
						),
					},
					{
						label: __( 'Next automatic update', 'lw-firewall' ),
						value: geo.nextUpdate
							? `${ until( geo.nextUpdate ) } (${ datetime(
									geo.nextUpdate
								) })`
							: __( 'not scheduled', 'lw-firewall' ),
					},
					geo.cacheDir && {
						label: __( 'Cache directory writable', 'lw-firewall' ),
						value: (
							<span className="lw-admin-stack">
								{ yesNo( geo.cacheDirWritable ) }
								<code className="lw-admin-code">
									{ geo.cacheDir }
								</code>
							</span>
						),
					},
					{
						label: __( '.htaccess country block', 'lw-firewall' ),
						help: __(
							'Blocks by the Cloudflare CF-IPCountry header before WordPress loads.',
							'lw-firewall'
						),
						value: geo.htaccessPresent
							? yesNo( geo.htaccessRules, geo.active )
							: __( 'No .htaccess file', 'lw-firewall' ),
					},
				] }
			/>
		</Section>
	);
}
