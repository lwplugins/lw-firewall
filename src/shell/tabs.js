/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';
import {
	cog,
	download,
	envelope,
	globe,
	info,
	key,
	listView,
	lock,
	notAllowed,
	people,
	shield,
} from '@wordpress/icons';

/**
 * Tab registry: hash slugs and order of the classic screen (?tab= honoured).
 * `save` = the tab edits lw_firewall options (top bar Save shown). `fields`
 * lists the option keys on the tab, so a failed save can flag the tabs that
 * hold an invalid field.
 */
export const TABS = [
	{
		id: 'general',
		label: __( 'General', 'lw-firewall' ),
		title: __( 'General Settings', 'lw-firewall' ),
		icon: cog,
		save: true,
		fields: [
			'enabled',
			'storage',
			'rate_limit',
			'rate_window',
			'action',
			'filter_params',
		],
	},
	{
		id: 'protection',
		label: __( 'Protection', 'lw-firewall' ),
		title: __( 'Protection', 'lw-firewall' ),
		icon: lock,
		save: true,
		prefixes: [ 'protect_', 'login_', 'auto_ban_' ],
	},
	{
		id: 'spam',
		label: __( 'Spam', 'lw-firewall' ),
		title: __( 'Spam', 'lw-firewall' ),
		icon: people,
		save: true,
		prefixes: [ 'register_', 'reset_' ],
	},
	{
		id: 'bots',
		label: __( 'Blocked Bots', 'lw-firewall' ),
		title: __( 'Blocked Bots', 'lw-firewall' ),
		icon: notAllowed,
		save: true,
		fields: [ 'blocked_bots' ],
	},
	{
		id: 'ip-rules',
		label: __( 'IP Rules', 'lw-firewall' ),
		title: __( 'IP Rules', 'lw-firewall' ),
		icon: key,
		save: true,
		fields: [
			'ip_whitelist',
			'ip_blacklist',
			'trusted_proxies',
			'proxy_header',
		],
	},
	{
		id: 'geo',
		label: __( 'Geo Blocking', 'lw-firewall' ),
		title: __( 'Geo Blocking', 'lw-firewall' ),
		icon: globe,
		save: true,
		fields: [ 'geo_enabled', 'blocked_countries' ],
	},
	{
		id: 'security',
		label: __( 'Security', 'lw-firewall' ),
		title: __( 'Security Headers', 'lw-firewall' ),
		icon: shield,
		save: true,
		fields: [ 'security_headers' ],
	},
	{
		id: 'alerts',
		label: __( 'Alerts', 'lw-firewall' ),
		title: __( 'New Administrator Alert', 'lw-firewall' ),
		icon: envelope,
		save: true,
		prefixes: [ 'admin_alert_' ],
	},
	{
		id: 'status',
		label: __( 'Status', 'lw-firewall' ),
		title: __( 'Firewall Status', 'lw-firewall' ),
		icon: info,
		save: false,
	},
	{
		id: 'logs',
		label: __( 'Logs', 'lw-firewall' ),
		title: __( 'Request Logging', 'lw-firewall' ),
		icon: listView,
		save: true,
		fields: [ 'log_enabled' ],
	},
	{
		id: 'import-export',
		label: __( 'Import / Export', 'lw-firewall' ),
		title: __( 'Import / Export', 'lw-firewall' ),
		icon: download,
		save: false,
	},
];

/**
 * Tab id that holds an option key (for error flags in the nav).
 *
 * @param {string} field Option key.
 * @return {string|undefined} Tab id.
 */
export const tabOfField = ( field ) =>
	TABS.find(
		( tab ) =>
			tab.fields?.includes( field ) ||
			tab.prefixes?.some( ( prefix ) => field.startsWith( prefix ) )
	)?.id;
