/**
 * LW Firewall: refresh a stale comment-form token.
 *
 * A full-page cache serves the token that was signed when the page was
 * cached. The first time a visitor focuses a comment form whose token is
 * older than half its lifetime, fetch a fresh one, so a long-cached page
 * never refuses a real comment. Everything fails open: without a response
 * the rendered token is submitted as before.
 */
( function () {
	'use strict';

	const FIELD = 'input[name="lw_fw_comment_token"]';

	function refresh( field ) {
		if ( field.getAttribute( 'data-lw-fw-done' ) ) {
			return;
		}
		field.setAttribute( 'data-lw-fw-done', '1' );

		const issued =
			parseInt( field.getAttribute( 'data-lw-fw-issued' ), 10 ) || 0;
		const stale =
			parseInt( field.getAttribute( 'data-lw-fw-stale' ), 10 ) || 3600;
		const url = field.getAttribute( 'data-lw-fw-refresh' );

		if ( ! url || ! window.fetch || Date.now() / 1000 - issued < stale ) {
			return;
		}

		const body = new window.FormData();
		body.append( 'action', 'lw_fw_comment_token' );

		window
			.fetch( url, {
				method: 'POST',
				body,
				credentials: 'same-origin',
			} )
			.then( function ( response ) {
				return response.ok ? response.json() : null;
			} )
			.then( function ( json ) {
				if ( json && json.success && json.data && json.data.token ) {
					field.value = json.data.token;
					field.setAttribute(
						'data-lw-fw-issued',
						String( json.data.issued )
					);
				}
			} )
			.catch( function () {} );
	}

	document.addEventListener( 'focusin', function ( event ) {
		const form = event.target && event.target.form;
		const field = form && form.querySelector( FIELD );

		if ( field ) {
			refresh( field );
		}
	} );
} )();
