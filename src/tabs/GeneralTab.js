/**
 * WordPress dependencies
 */
import { Button } from '@wordpress/components';
import { __, sprintf } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { NumberRow, SelectRow, SwitchRow } from '../components/Fields';
import ListRow from '../components/ListRow';
import Section from '../components/Section';

/**
 * Storage choices from meta.storage_backends; a backend the server reports as
 * unavailable stays selectable (auto-detect falls through) but says so.
 *
 * @param {Array} backends [ { value, label, available } ].
 * @return {Array} SelectControl options.
 */
const storageOptions = ( backends ) =>
	backends.map( ( b ) => ( {
		value: b.value,
		label: b.available
			? b.label
			: sprintf(
					/* translators: %s: storage backend name. */
					__( '%s (not available on this server)', 'lw-firewall' ),
					b.label
				),
	} ) );

export default function GeneralTab( { store } ) {
	const locked = store.isLocked( 'filter_params' );
	const filterDefaults = store.data.meta.filterParamsDefaults;

	return (
		<Section
			title={ __( 'General Settings', 'lw-firewall' ) }
			description={ __(
				'Core firewall settings — enable/disable, storage backend, rate limits and filter parameters.',
				'lw-firewall'
			) }
		>
			<SwitchRow
				title={ __( 'Enable Firewall', 'lw-firewall' ) }
				help={ __(
					'Master switch — when off, the MU-plugin worker performs no checks (rate-limit, bot blocking, IP/geo blocking, auto-ban all skipped).',
					'lw-firewall'
				) }
				store={ store }
				name="enabled"
				onText={ __( 'Enable firewall protection', 'lw-firewall' ) }
				offText={ __( 'Off', 'lw-firewall' ) }
			/>
			<SelectRow
				title={ __( 'Storage Backend', 'lw-firewall' ) }
				help={ __(
					'Storage backend for rate-limit counters. Auto-detect tries APCu, then Redis, then file.',
					'lw-firewall'
				) }
				store={ store }
				name="storage"
				options={ storageOptions( store.data.meta.storageBackends ) }
			/>
			<NumberRow
				title={ __( 'Rate Limit', 'lw-firewall' ) }
				help={ __(
					'Maximum number of rate-limited requests per IP within the time window. Applies to filter parameters, login, REST, XML-RPC and any other protected endpoint.',
					'lw-firewall'
				) }
				store={ store }
				name="rate_limit"
			/>
			<NumberRow
				title={ __( 'Time Window', 'lw-firewall' ) }
				help={ __(
					'Time window in seconds for rate limiting.',
					'lw-firewall'
				) }
				store={ store }
				name="rate_window"
				seconds
			/>
			<SelectRow
				title={ __( 'Rate Limit Action', 'lw-firewall' ) }
				help={ __(
					'Response when the rate limit is exceeded. 302 strips query parameters and redirects to the same path; 429 returns a Retry-After header.',
					'lw-firewall'
				) }
				store={ store }
				name="action"
				options={ [
					{
						value: 'redirect',
						label: __(
							'302 Redirect (strip filters)',
							'lw-firewall'
						),
					},
					{
						value: '429',
						label: __( '429 Too Many Requests', 'lw-firewall' ),
					},
				] }
			/>
			<ListRow
				title={ __( 'Filter Parameters', 'lw-firewall' ) }
				help={ __(
					'URL parameter substrings to rate-limit, one per line. Append |N for a stricter per-prefix limit (e.g. add-to-cart|10). Defaults: filter_|30, query_type_|30.',
					'lw-firewall'
				) }
				store={ store }
				name="filter_params"
				rows={ 4 }
				placeholder={ filterDefaults.join( '\n' ) }
				actions={
					filterDefaults.length > 0 && (
						<Button
							variant="link"
							disabled={ locked }
							onClick={ () =>
								store.set( 'filter_params', [
									...filterDefaults,
								] )
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
