/**
 * LW Firewall: passkey button of the two-factor login screen.
 *
 * Plain, unbuilt script (enqueued only when the user can use a passkey).
 * Reads the assertion options from the button, asks the browser for the
 * passkey, then posts the assertion with the challenge form. The challenge
 * itself stays on the server; the form only carries the signed answer.
 */
( function () {
	'use strict';

	var button = document.getElementById( 'lwfw-2fa-passkey-button' );
	var form = document.getElementById( 'lwfw-2fa-form' );
	var method = document.getElementById( 'lwfw-2fa-method' );
	var field = document.getElementById( 'lwfw-2fa-passkey' );

	if ( ! button || ! form || ! method || ! field ) {
		return;
	}

	if ( ! window.PublicKeyCredential || ! navigator.credentials ) {
		button.hidden = true;
		return;
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

	function publicKey() {
		var options = JSON.parse( button.getAttribute( 'data-options' ) || '{}' );
		var key = options.publicKey || {};
		key.challenge = toBuffer( key.challenge );
		if ( Array.isArray( key.allowCredentials ) ) {
			key.allowCredentials = key.allowCredentials.map( function ( cred ) {
				cred.id = toBuffer( cred.id );
				return cred;
			} );
		}
		return key;
	}

	function showError() {
		var message = button.getAttribute( 'data-error' ) || '';
		var box = document.getElementById( 'lwfw-2fa-passkey-error' );
		if ( ! box ) {
			box = document.createElement( 'p' );
			box.id = 'lwfw-2fa-passkey-error';
			box.setAttribute( 'role', 'alert' );
			button.parentNode.appendChild( box );
		}
		box.textContent = message;
	}

	button.addEventListener( 'click', function () {
		var request;
		try {
			request = navigator.credentials.get( { publicKey: publicKey() } );
		} catch ( e ) {
			showError();
			return;
		}

		button.disabled = true;
		request
			.then( function ( credential ) {
				var response = credential.response;
				field.value = JSON.stringify( {
					id: toB64url( credential.rawId ),
					clientDataJSON: toB64url( response.clientDataJSON ),
					authenticatorData: toB64url( response.authenticatorData ),
					signature: toB64url( response.signature ),
					userHandle: toB64url( response.userHandle ),
				} );
				method.value = 'passkey';
				form.submit();
			} )
			.catch( function () {
				button.disabled = false;
				showError();
			} );
	} );
} )();
