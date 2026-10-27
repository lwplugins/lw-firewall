/**
 * REST calls of the profile section (lw-firewall/v1/2fa/…). Cookie auth: the
 * wp-api-fetch nonce middleware sends X-WP-Nonce.
 */
/**
 * WordPress dependencies
 */
import apiFetch from '@wordpress/api-fetch';

const path = ( route ) => `/lw-firewall/v1/2fa${ route }`;
const send = ( route, method, data = {} ) =>
	apiFetch( { path: path( route ), method, data } );

export const api = {
	me: () => apiFetch( { path: path( '/me' ) } ),
	user: ( id ) => apiFetch( { path: path( `/users/${ id }` ) } ),
	totpBegin: ( proof ) => send( '/totp/begin', 'POST', proof ),
	totpConfirm: ( code ) => send( '/totp/confirm', 'POST', { code } ),
	totpDelete: ( proof ) => send( '/totp', 'DELETE', proof ),
	regenerate: ( proof ) => send( '/recovery/regenerate', 'POST', proof ),
	forgetDevices: ( proof ) => send( '/devices/forget', 'POST', proof ),
	passkeyBegin: ( proof ) => send( '/passkeys/begin', 'POST', proof ),
	passkeyFinish: ( data ) => send( '/passkeys/finish', 'POST', data ),
	passkeyDelete: ( id, proof ) =>
		send( `/passkeys/${ id }`, 'DELETE', proof ),
	reset: ( id, proof ) => send( `/users/${ id }/reset`, 'POST', proof ),
};

/**
 * Message of a failed call.
 *
 * @param {Object} error apiFetch rejection.
 * @return {string} Text.
 */
export const errorText = ( error ) => ( error && error.message ) || '';
