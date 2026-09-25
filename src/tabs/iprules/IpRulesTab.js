/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { SelectRow } from '../../components/Fields';
import ListRow from '../../components/ListRow';
import Section from '../../components/Section';
import BansSection from './BansSection';

export default function IpRulesTab( { store } ) {
	return (
		<>
			<Section
				title={ __( 'IP Rules', 'lw-firewall' ) }
				description={ __(
					'Manually allow or block IP addresses. Supports individual IPs and CIDR ranges (e.g. 192.168.1.0/24).',
					'lw-firewall'
				) }
			>
				<ListRow
					title={ __( 'IP Whitelist', 'lw-firewall' ) }
					help={ __(
						'IPs or CIDR ranges that bypass all firewall checks (one per line). Supports IPv4, IPv6, and CIDR notation (e.g. 10.0.0.0/8, 2001:db8::/32).',
						'lw-firewall'
					) }
					store={ store }
					name="ip_whitelist"
				/>
				<ListRow
					title={ __( 'IP Blacklist', 'lw-firewall' ) }
					help={ __(
						'IPs or CIDR ranges blocked with 403 Forbidden before any other check (one per line). Supports IPv4, IPv6, and CIDR notation.',
						'lw-firewall'
					) }
					store={ store }
					name="ip_blacklist"
				/>
			</Section>
			<Section
				title={ __( 'Reverse Proxy', 'lw-firewall' ) }
				description={ __(
					'Leave this empty unless the site sits behind a proxy or load balancer. A forwarded-for header is written by the client until the hop that set it is known, so trusting one without listing the proxies would let any visitor choose their own IP — and with it their own rate-limit bucket, ban status and country. Cloudflare is handled automatically and needs nothing here.',
					'lw-firewall'
				) }
			>
				<ListRow
					title={ __( 'Trusted Proxies', 'lw-firewall' ) }
					help={ __(
						'IPs or CIDR ranges of your own proxies, one per line. On the common "nginx in front of Apache on the same host" layout this is 127.0.0.1 — without it every visitor arrives as 127.0.0.1 and shares a single bucket.',
						'lw-firewall'
					) }
					store={ store }
					name="trusted_proxies"
					rows={ 4 }
				/>
				<SelectRow
					title={ __( 'Forwarded Header', 'lw-firewall' ) }
					help={ __(
						'Read right to left, skipping hops that are themselves listed above. Only used when a trusted proxy is configured.',
						'lw-firewall'
					) }
					store={ store }
					name="proxy_header"
					options={ [
						{ value: 'x-forwarded-for', label: 'X-Forwarded-For' },
						{ value: 'x-real-ip', label: 'X-Real-IP' },
						{ value: 'forwarded', label: 'Forwarded (RFC 7239)' },
					] }
				/>
			</Section>
			<BansSection store={ store } />
		</>
	);
}
