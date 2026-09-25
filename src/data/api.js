/**
 * Every REST call the admin makes, in one place. Responses
 * go through ./shapes before the UI reads them, so a backend shape change is
 * a one-file fix there.
 */
/**
 * WordPress dependencies
 */
import apiFetch from '@wordpress/api-fetch';
import { addQueryArgs } from '@wordpress/url';

/**
 * Internal dependencies
 */
import { NAMESPACE } from './boot';
import {
	toBanResult,
	toBans,
	toGeoResult,
	toImportResult,
	toLogs,
	toScanResult,
	toSettings,
	toStatus,
	toTestResult,
	toUnbanResult,
	toWorkerResult,
} from './shapes';

const path = ( route ) => `/${ NAMESPACE }/admin${ route }`;
const get = ( route, args, signal ) =>
	apiFetch( { path: addQueryArgs( path( route ), args ), signal } );
const send = ( route, method, data ) =>
	apiFetch( { path: path( route ), method, data } );

export const api = {
	// Settings: GET → { options, meta }; POST any subset → same shape.
	settings: () => get( '/settings' ).then( toSettings ),
	saveSettings: ( patch ) =>
		send( '/settings', 'POST', patch ).then( toSettings ),

	// Bans. Every write answers with the fresh list (`bans`).
	bans: () => get( '/bans' ).then( toBans ),
	ban: ( ip, duration ) =>
		send(
			'/bans',
			'POST',
			duration === '' || duration === undefined
				? { ip }
				: { ip, duration: Number( duration ) }
		).then( toBanResult ),
	unbanIps: ( ips ) =>
		send( '/bans/unban', 'POST', { ips } ).then( toUnbanResult ),
	unbanUsers: ( users ) =>
		send( '/bans/unban', 'POST', { users } ).then( toUnbanResult ),
	unbanAll: () =>
		send( '/bans/unban', 'POST', { all: true } ).then( toUnbanResult ),

	// Logs, server-paged (per_page 1–100).
	logs: ( { page, perPage, reason, search }, signal ) =>
		get(
			'/logs',
			{
				page,
				per_page: Math.min( 100, perPage ),
				reason: reason || undefined,
				search: search || undefined,
			},
			signal
		).then( toLogs ),
	clearLogs: () => send( '/logs', 'DELETE' ),

	// Maintenance actions.
	reinstallWorker: () =>
		send( '/worker/reinstall', 'POST' ).then( toWorkerResult ),
	// One country per request keeps each download short.
	updateGeo: ( cc ) =>
		send( '/geo/update', 'POST', { countries: [ cc ] } ).then(
			toGeoResult
		),
	scanAlerts: () => send( '/alerts/scan', 'POST' ).then( toScanResult ),
	testAlert: () => send( '/alerts/test', 'POST' ).then( toTestResult ),

	// Import / export.
	exportSettings: () => get( '/export' ),
	importSettings: ( json ) =>
		send( '/import', 'POST', { json } ).then( toImportResult ),

	// Status.
	status: () => get( '/status' ).then( toStatus ),
};

/**
 * Human message of a failed request.
 *
 * @param {Object} error apiFetch rejection.
 * @return {string} Message.
 */
export const errorMessage = ( error ) =>
	error?.message ||
	'That did not work. Please reload the page and try again.';

/**
 * Per-field validation errors of a `400 lw_firewall_invalid` response.
 *
 * @param {Object} error apiFetch rejection.
 * @return {Object|null} { key: [ messages ] } or null.
 */
export function fieldErrors( error ) {
	const fields = error?.data?.fields;
	if ( ! fields || typeof fields !== 'object' ) {
		return null;
	}
	return Object.fromEntries(
		Object.entries( fields ).map( ( [ key, messages ] ) => [
			key,
			( Array.isArray( messages ) ? messages : [ messages ] ).map(
				String
			),
		] )
	);
}
