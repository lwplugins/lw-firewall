/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import CountryPicker from '../../components/CountryPicker';
import { SwitchRow } from '../../components/Fields';
import ListRow from '../../components/ListRow';
import Section from '../../components/Section';
import CidrUpdate from './CidrUpdate';

export default function GeoTab( { store, status } ) {
	const hasCountryList = store.data.meta.countries.length > 0;

	return (
		<Section
			title={ __( 'Geo Blocking', 'lw-firewall' ) }
			description={ __(
				'Block visitors from specific countries. Behind Cloudflare, the CF-IPCountry header is used (instant). Without Cloudflare, CIDR-based lookup is used (updated weekly).',
				'lw-firewall'
			) }
		>
			<SwitchRow
				title={ __( 'Enable', 'lw-firewall' ) }
				store={ store }
				name="geo_enabled"
				onText={ __( 'Enable Geo Blocking', 'lw-firewall' ) }
				offText={ __( 'Off', 'lw-firewall' ) }
			/>
			{ hasCountryList ? (
				<CountryPicker
					title={ __( 'Blocked Countries', 'lw-firewall' ) }
					help={ __(
						'Visitors from the selected countries are blocked with 403.',
						'lw-firewall'
					) }
					store={ store }
					name="blocked_countries"
				/>
			) : (
				<ListRow
					title={ __( 'Blocked Countries', 'lw-firewall' ) }
					help={ __(
						'ISO 3166–1 alpha-2 country codes, one per line (e.g. IN, CN, RU).',
						'lw-firewall'
					) }
					store={ store }
					name="blocked_countries"
				/>
			) }
			<CidrUpdate store={ store } status={ status } />
		</Section>
	);
}
