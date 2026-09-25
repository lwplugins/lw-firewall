/**
 * WordPress dependencies
 */
import { Button } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import ListRow from '../components/ListRow';
import Section from '../components/Section';

export default function BotsTab( { store } ) {
	const defaults = store.data.meta.botsDefaults;

	return (
		<Section
			title={ __( 'Blocked Bots', 'lw-firewall' ) }
			description={ __(
				'User-Agent strings to block (one per line, case-insensitive substring match).',
				'lw-firewall'
			) }
		>
			<ListRow
				title={ __( 'Blocked User-Agents', 'lw-firewall' ) }
				help={ __(
					'User-Agent substrings (case-insensitive, one per line). Any request whose User-Agent contains one of these is blocked with 403.',
					'lw-firewall'
				) }
				store={ store }
				name="blocked_bots"
				rows={ 12 }
				actions={
					defaults.length > 0 && (
						<Button
							variant="link"
							disabled={ store.isLocked( 'blocked_bots' ) }
							onClick={ () =>
								store.set( 'blocked_bots', [ ...defaults ] )
							}
						>
							{ __( 'Restore defaults', 'lw-firewall' ) }
						</Button>
					)
				}
			/>
		</Section>
	);
}
