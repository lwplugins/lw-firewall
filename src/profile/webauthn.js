/**
 * navigator.credentials.create() for a new passkey and .get() for a passkey
 * re-authentication. The options come from PasskeyService (base64url binary
 * fields); the responses go back as base64url text.
 */

const toBuffer = ( b64url ) => {
	let b64 = String( b64url || '' )
		.replace( /-/g, '+' )
		.replace( /_/g, '/' );
	while ( b64.length % 4 ) {
		b64 += '=';
	}
	const bin = window.atob( b64 );
	const out = new Uint8Array( bin.length );
	for ( let i = 0; i < bin.length; i++ ) {
		out[ i ] = bin.charCodeAt( i );
	}
	return out.buffer;
};

const toB64url = ( buffer ) => {
	const bytes = new Uint8Array( buffer || new ArrayBuffer( 0 ) );
	let bin = '';
	for ( let i = 0; i < bytes.length; i++ ) {
		bin += String.fromCharCode( bytes[ i ] );
	}
	return window
		.btoa( bin )
		.replace( /\+/g, '-' )
		.replace( /\//g, '_' )
		.replace( /=+$/, '' );
};

/**
 * Whether this browser can create passkeys.
 *
 * @return {boolean} Support.
 */
export const supported = () =>
	!! ( window.PublicKeyCredential && navigator.credentials );

/**
 * Run the browser ceremony.
 *
 * @param {Object} options { publicKey } from the begin route.
 * @return {Promise<Object>} { clientDataJSON, attestationObject }.
 */
export async function createPasskey( options ) {
	const key = { ...( ( options && options.publicKey ) || {} ) };
	key.challenge = toBuffer( key.challenge );
	key.user = { ...key.user, id: toBuffer( key.user && key.user.id ) };
	if ( Array.isArray( key.excludeCredentials ) ) {
		key.excludeCredentials = key.excludeCredentials.map( ( cred ) => ( {
			...cred,
			id: toBuffer( cred.id ),
		} ) );
	}

	const credential = await navigator.credentials.create( { publicKey: key } );

	return {
		clientDataJSON: toB64url( credential.response.clientDataJSON ),
		attestationObject: toB64url( credential.response.attestationObject ),
	};
}

/**
 * Sign a re-authentication challenge with one of the user's passkeys.
 *
 * @param {Object} options { publicKey } from /reauth/passkey/options.
 * @return {Promise<Object>} { id, clientDataJSON, authenticatorData, signature, userHandle }.
 */
export async function getPasskey( options ) {
	const key = { ...( ( options && options.publicKey ) || {} ) };
	key.challenge = toBuffer( key.challenge );
	if ( Array.isArray( key.allowCredentials ) ) {
		key.allowCredentials = key.allowCredentials.map( ( cred ) => ( {
			...cred,
			id: toBuffer( cred.id ),
		} ) );
	}

	const credential = await navigator.credentials.get( { publicKey: key } );
	const response = credential.response;

	return {
		id: toB64url( credential.rawId ),
		clientDataJSON: toB64url( response.clientDataJSON ),
		authenticatorData: toB64url( response.authenticatorData ),
		signature: toB64url( response.signature ),
		userHandle: toB64url( response.userHandle ),
	};
}
