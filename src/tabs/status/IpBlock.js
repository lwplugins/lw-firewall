/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import Callout from '../../components/Callout';
import KeyValue from '../../components/KeyValue';
import Section from '../../components/Section';
import yesNo from './yesNo';

const code = ( value ) => ( value ? <code>{ value }</code> : '—' );

const sourceLabel = ( source ) =>
	( {
		cloudflare: __( 'Cloudflare header (CF-Connecting-IP)', 'lw-firewall' ),
		trusted_proxy: __(
			'Forwarded header from a trusted proxy',
			'lw-firewall'
		),
		remote_addr: __( 'The connection itself (REMOTE_ADDR)', 'lw-firewall' ),
	} )[ source ] || source;

/**
 * How the firewall sees THIS request: where the address came from, the
 * forwarded headers, proxy trust, and whether the address is counted.
 *
 * @param {Object} props
 * @param {Object} props.ip Status client_ip block.
 */
export default function IpBlock( { ip } ) {
	return (
		<Section
			title={ __( 'Client IP detection', 'lw-firewall' ) }
			description={ __(
				'How the firewall sees your own request right now. Every visitor is identified the same way, so a wrong address here means shared rate-limit buckets and bans.',
				'lw-firewall'
			) }
		>
			{ ! ip.counted && (
				<Callout tone="warning">
					{ __(
						'This address is not counted or banned: it is private, shared or one of your trusted proxies. Blacklist, whitelist, geo and bot checks still apply to it.',
						'lw-firewall'
					) }
				</Callout>
			) }
			<KeyValue
				rows={ [
					{
						label: __( 'Detected IP', 'lw-firewall' ),
						value: code( ip.detected ),
					},
					{
						label: __( 'Taken from', 'lw-firewall' ),
						value: sourceLabel( ip.source ),
					},
					{ label: 'REMOTE_ADDR', value: code( ip.remoteAddr ) },
					{
						label: __( 'Forwarded headers', 'lw-firewall' ),
						value: ip.headers.length ? (
							<ul className="lw-admin-plain">
								{ ip.headers.map( ( h ) => (
									<li key={ h.name }>
										<code>{ h.name }</code>{ ' ' }
										<code className="lw-admin-code">
											{ h.value }
										</code>
									</li>
								) ) }
							</ul>
						) : (
							__( 'none', 'lw-firewall' )
						),
					},
					{
						label: __(
							'Trusted proxies configured',
							'lw-firewall'
						),
						value: yesNo(
							ip.proxiesConfigured,
							ip.proxiesConfigured
						),
					},
					ip.proxiesConfigured && {
						label: __( 'Trusted proxy match', 'lw-firewall' ),
						help: __(
							'Whether REMOTE_ADDR is one of the Trusted Proxies on the IP Rules tab.',
							'lw-firewall'
						),
						value: yesNo( ip.trustedProxyMatch ),
					},
					ip.proxiesConfigured && {
						label: __( 'Forwarded Header', 'lw-firewall' ),
						value: code( ip.proxyHeader ),
					},
					{
						label: __( 'Cloudflare detected', 'lw-firewall' ),
						value: yesNo( ip.cloudflare, ip.cloudflare ),
					},
					{
						label: __( 'Routable', 'lw-firewall' ),
						help: __(
							'A private or reserved address means all visitors share one bucket.',
							'lw-firewall'
						),
						value: yesNo( ip.routable ),
					},
					{
						label: __( 'Counted and bannable', 'lw-firewall' ),
						value: yesNo( ip.counted ),
					},
				] }
			/>
		</Section>
	);
}
