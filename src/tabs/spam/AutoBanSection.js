/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { NumberRow } from '../../components/Fields';
import Section from '../../components/Section';

/**
 * Shared auto-ban for rejected registrations, comments and reviews.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store.
 */
export default function AutoBanSection( { store } ) {
	return (
		<Section
			title={ __( 'Spam Auto-Ban', 'lw-firewall' ) }
			description={ __(
				'Ban IPs that repeatedly send spam registrations, comments or reviews. A banned IP is blocked from the whole site, not just the form.',
				'lw-firewall'
			) }
		>
			<NumberRow
				title={ __( 'Ban Threshold', 'lw-firewall' ) }
				help={ __(
					'Number of rejected registrations, comments and reviews (counted together) from one IP before it is banned. A comment refused only because its form was too old is not counted.',
					'lw-firewall'
				) }
				store={ store }
				name="register_ban_threshold"
			/>
			<NumberRow
				title={ __( 'Ban Duration', 'lw-firewall' ) }
				help={ __(
					'How long the ban lasts in seconds (3600 = 1 hour).',
					'lw-firewall'
				) }
				store={ store }
				name="register_ban_duration"
				seconds
			/>
		</Section>
	);
}
