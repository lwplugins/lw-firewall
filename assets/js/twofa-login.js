/**
 * LW Firewall: passkey buttons of the login screens.
 *
 * Plain, unbuilt script. Two independent parts:
 *
 * - the two-factor screen: reads the assertion options from the button, asks
 *   the browser for the passkey, then posts the assertion with the challenge
 *   form;
 * - the login form (passwordless): asks the REST options route for a fresh
 *   discoverable challenge, lets the browser pick the account's passkey,
 *   posts the assertion to the verify route and follows its redirect.
 *
 * The challenges stay on the server; the browser only carries signed answers.
 */
( function () {
	'use strict';

	function supported() {
		return !! ( window.PublicKeyCredential && navigator.credentials );
	}

	function toBuffer( b64url ) {
		var b64 = String( b64url ).replace( /-/g, '+' ).replace( /_/g, '/' );
		while ( b64.length % 4 ) {
			b64 += '=';
		}
		var bin = window.atob( b64 );
		var out = new Uint8Array( bin.length );
		for ( var i = 0; i < bin.length; i++ ) {
			out[ i ] = bin.charCodeAt( i );
		}
		return out.buffer;
	}

	function toB64url( buffer ) {
		if ( ! buffer ) {
			return '';
		}
		var bytes = new Uint8Array( buffer );
		var bin = '';
		for ( var i = 0; i < bytes.length; i++ ) {
			bin += String.fromCharCode( bytes[ i ] );
		}
		return window.btoa( bin ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	function publicKey( options ) {
		var key = ( options && options.publicKey ) || {};
		key.challenge = toBuffer( key.challenge );
		if ( Array.isArray( key.allowCredentials ) ) {
			key.allowCredentials = key.allowCredentials.map( function ( cred ) {
				cred.id = toBuffer( cred.id );
				return cred;
			} );
		}
		return key;
	}

	function assertion( credential ) {
		var response = credential.response;
		return {
			id: toB64url( credential.rawId ),
			clientDataJSON: toB64url( response.clientDataJSON ),
			authenticatorData: toB64url( response.authenticatorData ),
			signature: toB64url( response.signature ),
			userHandle: toB64url( response.userHandle ),
		};
	}

	function showError( anchor, id, message ) {
		var box = document.getElementById( id );
		if ( ! box ) {
			box = document.createElement( 'p' );
			box.id = id;
			box.setAttribute( 'role', 'alert' );
			anchor.parentNode.appendChild( box );
		}
		box.textContent = message;
	}

	function setupChallenge() {
		var button = document.getElementById( 'lwfw-2fa-passkey-button' );
		var form = document.getElementById( 'lwfw-2fa-form' );
		var method = document.getElementById( 'lwfw-2fa-method' );
		var field = document.getElementById( 'lwfw-2fa-passkey' );

		if ( ! button || ! form || ! method || ! field ) {
			return;
		}

		if ( ! supported() ) {
			button.hidden = true;
			return;
		}

		var error = button.getAttribute( 'data-error' ) || '';

		button.addEventListener( 'click', function () {
			var request;
			try {
				request = navigator.credentials.get( {
					publicKey: publicKey( JSON.parse( button.getAttribute( 'data-options' ) || '{}' ) ),
				} );
			} catch ( e ) {
				showError( button, 'lwfw-2fa-passkey-error', error );
				return;
			}

			button.disabled = true;
			request
				.then( function ( credential ) {
					field.value = JSON.stringify( assertion( credential ) );
					method.value = 'passkey';
					form.submit();
				} )
				.catch( function () {
					button.disabled = false;
					showError( button, 'lwfw-2fa-passkey-error', error );
				} );
		} );
	}

	// Rejects with { server: message } on an error answer (the message is the
	// site's own translated text; browser errors are never shown verbatim).
	function post( url, body ) {
		return window
			.fetch( url, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify( body ),
			} )
			.then( function ( response ) {
				return response
					.json()
					.catch( function () {
						return {};
					} )
					.then( function ( data ) {
						if ( ! response.ok ) {
							throw { server: data && typeof data.message === 'string' ? data.message : '' };
						}
						return data;
					} );
			} );
	}

	function setupLogin() {
		var box = document.getElementById( 'lwfw-passkey-login' );
		var button = document.getElementById( 'lwfw-passkey-login-button' );

		if ( ! box || ! button || ! supported() || ! window.fetch ) {
			return;
		}

		var form = box.closest( 'form' );
		var fallback = box.getAttribute( 'data-error' ) || '';
		box.hidden = false;

		button.addEventListener( 'click', function () {
			var remember = document.getElementById( 'rememberme' );
			var redirect = form ? form.querySelector( 'input[name="redirect_to"]' ) : null;

			button.disabled = true;
			post( box.getAttribute( 'data-options-url' ), {} )
				.then( function ( challenge ) {
					return navigator.credentials
						.get( { publicKey: publicKey( challenge.options ) } )
						.then( function ( credential ) {
							return post( box.getAttribute( 'data-verify-url' ), {
								key: challenge.key,
								credential: assertion( credential ),
								remember: !! ( remember && remember.checked ),
								redirect_to: redirect ? redirect.value : '',
							} );
						} );
				} )
				.then( function ( result ) {
					if ( ! result || typeof result.redirect !== 'string' ) {
						throw { server: '' };
					}
					window.location.assign( result.redirect );
				} )
				.catch( function ( e ) {
					button.disabled = false;
					showError( button, 'lwfw-passkey-login-error', ( e && e.server ) || fallback );
				} );
		} );
	}

	setupChallenge();
	setupLogin();
} )();
