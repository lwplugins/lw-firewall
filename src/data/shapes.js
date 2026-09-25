/**
 * Response adapters: the ONLY place that knows the backend's field names
 * (lw-firewall/v1 admin routes, 1.6.0). The UI reads the camelCase objects
 * built here.
 */

const obj = ( value ) =>
	value && typeof value === 'object' && ! Array.isArray( value ) ? value : {};
const list = ( value ) => ( Array.isArray( value ) ? value : [] );
const num = ( value ) => Number( value ) || 0;

// Settings ------------------------------------------------------------------

/**
 * Localised country name (Intl.DisplayNames in the admin locale), falling
 * back to the English name the server sends.
 *
 * @return {Function} ( code, english ) => name.
 */
function regionNamer() {
	let names = null;
	try {
		const locale = ( document.documentElement.lang || 'en' ).replace(
			'_',
			'-'
		);
		names = new Intl.DisplayNames( [ locale, 'en' ], { type: 'region' } );
	} catch {
		names = null;
	}
	return ( code, english ) => {
		try {
			const name = names?.of( code );
			return name && name !== code ? name : english;
		} catch {
			return english;
		}
	};
}

/**
 * GET/POST /admin/settings → { options, meta }. Options hold EFFECTIVE values
 * (a key pinned in wp-config.php shows the constant's value).
 *
 * @param {Object} data Response.
 * @return {Object} { options, meta }.
 */
export function toSettings( data ) {
	const meta = obj( data?.meta );
	const server = obj( meta.server );
	const nameOf = regionNamer();

	return {
		options: obj( data?.options ),
		meta: {
			locked: list( meta.locked ),
			lockedConstants: obj( meta.locked_constants ),
			defaults: obj( meta.defaults ),
			ranges: obj( meta.ranges ),
			enums: obj( meta.enums ),
			storageBackends: list( meta.storage_backends ).map( ( b ) => ( {
				value: String( b.value ),
				label: String( b.label ),
				available: !! b.available,
			} ) ),
			countries: Object.entries( obj( meta.countries ) )
				.map( ( [ code, english ] ) => ( {
					code,
					name: nameOf( code, String( english ) ),
				} ) )
				.sort( ( a, b ) => a.name.localeCompare( b.name ) ),
			botsDefaults: list( meta.bots_defaults ),
			filterParamsDefaults: list( meta.filter_params_defaults ),
			adminEmail: server.admin_email || '',
			usersCanRegister: !! server.users_can_register,
			muPluginsDir: server.mu_plugins_dir || '',
			securityHeaders: list( server.security_headers ),
			geoNextUpdate: num( server.geo_next_update ),
			cloudflare: !! server.cloudflare,
			storageActive: server.storage_active || '',
			docsUrl: meta.docs_url || '',
		},
	};
}

// Bans ----------------------------------------------------------------------

/**
 * GET /admin/bans (also `bans` inside unban / ban responses).
 *
 * @param {Object} data Response.
 * @return {Object} { items, userLocks, summary, store, reasons }.
 */
export function toBans( data ) {
	const summary = obj( data?.summary );
	const store = obj( data?.store );

	return {
		items: list( data?.items ).map( ( row ) => ( {
			id: `ip:${ row.ip }`,
			ip: String( row.ip ),
			kind: row.kind || 'ip', // ip | network (IPv6 /64) | legacy
			reason: row.reason || '',
			reasonLabel: row.reason_label || '',
			reasonHint: row.reason_hint || '',
			source: row.source || 'unknown',
			time: num( row.time ),
			expires: num( row.expires ),
			active: !! row.active,
		} ) ),
		userLocks: list( data?.user_locks ).map( ( lock ) => ( {
			id: `user:${ lock.key }`,
			key: String( lock.key ),
			user: String( lock.user ?? '' ),
			time: num( lock.time ),
			expires: num( lock.expires ),
			active: !! lock.active,
		} ) ),
		summary: {
			total: num( summary.total ),
			enforced: num( summary.enforced ),
			trackedOnly: num( summary.tracked_only ),
			expiringSoon: num( summary.expiring_soon ),
		},
		store: {
			preference: store.preference || '',
			backend: store.backend || '',
			label: store.label || '',
		},
		reasons: Object.fromEntries(
			Object.entries( obj( data?.reasons ) ).map( ( [ code, r ] ) => [
				code,
				{ label: r?.label || code, hint: r?.hint || '' },
			] )
		),
	};
}

/**
 * POST /admin/bans/unban → per-address and per-username results + the fresh
 * list.
 *
 * @param {Object} data Response.
 * @return {Object} { results, bans }.
 */
export const toUnbanResult = ( data ) => ( {
	results: [
		...list( data?.results ).map( ( r ) => ( {
			label: String( r.ip ),
			ok: !! r.ok,
			message: r.message || '',
		} ) ),
		...list( data?.user_results ).map( ( r ) => ( {
			label: String( r.user || r.key ),
			ok: !! r.ok,
			message: r.message || '',
		} ) ),
	],
	bans: data?.bans ? toBans( data.bans ) : null,
} );

/**
 * POST /admin/bans → { ok, ip, message, bans }.
 *
 * @param {Object} data Response.
 * @return {Object} Result.
 */
export const toBanResult = ( data ) => ( {
	ok: !! data?.ok,
	ip: data?.ip || '',
	message: data?.message || '',
	bans: data?.bans ? toBans( data.bans ) : null,
} );

// Logs ----------------------------------------------------------------------

/**
 * GET /admin/logs → one page.
 *
 * @param {Object} data Response.
 * @return {Object} { items, total, totalPages, reasons, enabled }.
 */
export function toLogs( data ) {
	return {
		items: list( data?.items ).map( ( e, index ) => ( {
			id: `${ data?.page || 1 }-${ index }-${ e.time }-${ e.ip }`,
			time: e.time,
			ip: e.ip || '',
			reason: e.reason_code || e.reason || '',
			reasonLabel: e.reason_label || e.reason_code || '',
			ua: e.ua || '',
			url: e.url || '',
		} ) ),
		total: num( data?.total ),
		totalPages: Math.max( 1, num( data?.pages ) ),
		reasons: Object.entries( obj( data?.reasons ) ).map(
			( [ value, label ] ) => ( { value, label: String( label ) } )
		),
		enabled: !! data?.enabled,
	};
}

// Actions -------------------------------------------------------------------

export const toWorkerResult = ( data ) => ( {
	ok: !! data?.ok,
	message: data?.message || '',
} );

export const toGeoResult = ( data ) => ( {
	results: list( data?.results ).map( ( r ) => ( {
		cc: String( r.cc ).toUpperCase(),
		v4: !! r.v4,
		v6: !! r.v6,
		message: r.message || '',
	} ) ),
	message: data?.message || '',
} );

export const toScanResult = ( data ) => ( {
	state: data?.state || '',
	sent: !! data?.sent,
	queued: !! data?.queued,
	message: data?.message || '',
} );

export const toTestResult = ( data ) => ( {
	sent: !! data?.sent,
	error: data?.error || '',
	message: data?.message || '',
	recipients: list( data?.recipients ),
} );

/**
 * POST /admin/import → { settings, report }. Import is NOT atomic: valid
 * keys are applied, the rest reported.
 *
 * @param {Object} data Response.
 * @return {Object} Result.
 */
export const toImportResult = ( data ) => {
	const report = obj( data?.report );
	return {
		settings: data?.options ? toSettings( data ) : null,
		report: {
			imported: list( report.imported ),
			invalid: obj( report.invalid ),
			locked: list( report.locked ),
			unknown: list( report.unknown ),
		},
	};
};

// Status --------------------------------------------------------------------

/**
 * GET /admin/status → the blocks the Status, Alerts and Geo tabs render.
 *
 * @param {Object} data Response.
 * @return {Object} Status.
 */
export function toStatus( data ) {
	const f = obj( data?.firewall );
	const w = obj( data?.worker );
	const s = obj( data?.storage );
	const i = obj( data?.client_ip );
	const g = obj( data?.geo );
	const a = obj( data?.alerts );
	const attempt = w.last_attempt ? obj( w.last_attempt ) : null;

	return {
		warnings: list( data?.warnings ).map( ( item ) => ( {
			code: item.code || '',
			severity: item.severity || 'warning',
			message: item.message || '',
		} ) ),
		firewall: {
			enabled: !! f.enabled,
			version: f.version || '',
			php: f.php_version || '',
			wp: f.wp_version || '',
		},
		worker: {
			installed: !! w.installed,
			version: w.version || '',
			expected: w.expected || '',
			versionMatch: !! w.version_match,
			outdated: !! w.outdated,
			killSwitch: !! w.kill_switch,
			muDir: w.mu_dir || '',
			muWritable: !! w.mu_dir_writable,
			lastSeen: num( w.last_seen ),
			heartbeatAge:
				w.heartbeat_age === null || w.heartbeat_age === undefined
					? null
					: num( w.heartbeat_age ),
			lastAttempt: attempt && {
				success: !! attempt.success,
				message: attempt.message || '',
				time: num( attempt.time ),
			},
		},
		storage: {
			preference: s.preference || '',
			active: s.active || '',
			backend: s.backend || '',
			probe: s.probe
				? { ok: !! s.probe.ok, message: s.probe.message || '' }
				: null,
			fileDir: s.file_dir || '',
			fileDirWritable: !! s.file_dir_writable,
		},
		ip: {
			detected: i.detected_ip || '',
			remoteAddr: i.remote_addr || '',
			source: i.source || 'remote_addr', // cloudflare | trusted_proxy | remote_addr
			cloudflare: !! i.cloudflare,
			proxiesConfigured: !! i.proxies_configured,
			trustedProxyMatch: !! i.trusted_proxy_match,
			proxyHeader: i.proxy_header || '',
			headers: list( i.forwarded_headers ).map( ( h ) => ( {
				name: String( h.name ),
				value: String( h.value ),
			} ) ),
			routable: !! i.routable,
			counted: i.counted !== false,
		},
		geo: {
			enabled: !! g.enabled,
			active: !! g.active,
			nextUpdate: num( g.next_update ),
			countries: list( g.countries ).map( ( c ) => ( {
				cc: String( c.cc ).toUpperCase(),
				stale: !! c.stale,
			} ) ),
			cacheDir: g.cache_dir || '',
			cacheDirWritable: !! g.cache_dir_writable,
			htaccessPresent: !! g.htaccess_present,
			htaccessRules: !! g.htaccess_rules,
		},
		alerts: {
			enabled: !! a.enabled,
			adminsTracked: num( a.admins_tracked ),
			recipients: list( a.recipients ).join( ', ' ),
			snapshot: num( a.snapshot_time ),
			nextScan: num( a.next_scan ),
			pending: num( a.pending ),
			mailError: !! a.mail_error,
		},
	};
}
