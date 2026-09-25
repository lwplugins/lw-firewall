/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import KeyValue from '../../components/KeyValue';
import Section from '../../components/Section';
import { VERSION } from '../../data/boot';

const code = ( value ) => ( value ? <code>{ value }</code> : '—' );

/**
 * Versions block.
 *
 * @param {Object} props
 * @param {Object} props.firewall Status firewall block.
 * @param {Object} props.worker   Status worker block.
 */
export default function VersionsBlock( { firewall, worker } ) {
	return (
		<Section title={ __( 'Versions', 'lw-firewall' ) }>
			<KeyValue
				rows={ [
					{
						label: __( 'Plugin', 'lw-firewall' ),
						value: code( firewall.version || VERSION ),
					},
					{
						label: __( 'Worker', 'lw-firewall' ),
						value: code( worker.version ),
					},
					{ label: 'PHP', value: code( firewall.php ) },
					{ label: 'WordPress', value: code( firewall.wp ) },
				] }
			/>
		</Section>
	);
}
