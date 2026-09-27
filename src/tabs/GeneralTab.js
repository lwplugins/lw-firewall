/**
 * WordPress dependencies
 */
import { __, sprintf } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { NumberRow, SelectRow, SwitchRow } from '../components/Fields';
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
	return (
		<Section
			title={ __( 'General Settings', 'lw-firewall' ) }
			description={ __(
				'Core firewall settings — enable/disable, storage backend, rate limits and WooCommerce filter protection.',
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
					'Maximum number of rate-limited requests per IP within the time window. Applies to WooCommerce filters, login, REST, XML-RPC and any other protected endpoint.',
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
			<SwitchRow
				title={ __( 'WooCommerce Filters', 'lw-firewall' ) }
				help={ __(
					'WooCommerce product-filter URLs (filter_*, query_type_*, min_price, max_price, rating_filter and the Product Filters block arguments) are served only to visitors carrying a cookie that every page sets from JavaScript. Without it, a tiny page sets the cookie and reloads the same URL, so real visitors barely notice, while bot networks sending one request per IP never reach WooCommerce. Signed-in users and whitelisted IPs are not challenged. The per-IP rate limit above still applies to filter requests.',
					'lw-firewall'
				) }
				store={ store }
				name="filter_require_cookie"
				onText={ __(
					'Require the visitor cookie for filter requests',
					'lw-firewall'
				) }
				offText={ __( 'Off', 'lw-firewall' ) }
			/>
			<SwitchRow
				title={ __( 'Allow Googlebot', 'lw-firewall' ) }
				help={ __(
					'Let a genuine Googlebot (verified by reverse and forward DNS, cached for a day) request filter URLs without the cookie. Usually best left off: indexing filter combinations wastes crawl budget.',
					'lw-firewall'
				) }
				store={ store }
				name="filter_cookie_allow_googlebot"
				onText={ __(
					'Skip the check for verified Googlebot',
					'lw-firewall'
				) }
				offText={ __( 'Off', 'lw-firewall' ) }
			/>
		</Section>
	);
}
