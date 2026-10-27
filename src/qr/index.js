/**
 * LW Firewall: QR code for authenticator setup (shared entry, build/qr.js).
 *
 * Exposes window.lwFirewallQr.render( element, text ) and draws into every
 * element with a `data-lwfw-qr` attribute on load (the forced-enrollment
 * screen on wp-login.php). The SVG is built with DOM calls, never innerHTML.
 */
/**
 * External dependencies
 */
import qrcode from 'qrcode-generator';

const SVG_NS = 'http://www.w3.org/2000/svg';
const QUIET = 4;

/**
 * Replace the element's content with an SVG QR code of the text.
 *
 * @param {Element} element Target.
 * @param {string}  text    Text to encode (an otpauth:// URI).
 * @param {number}  size    Rendered size in CSS pixels.
 * @return {boolean} Whether a code was drawn.
 */
export function render( element, text, size = 192 ) {
	if ( ! element || ! text ) {
		return false;
	}

	let qr;
	try {
		qr = qrcode( 0, 'M' );
		qr.addData( String( text ), 'Byte' );
		qr.make();
	} catch {
		return false;
	}

	const count = qr.getModuleCount();
	const total = count + QUIET * 2;
	let path = '';
	for ( let row = 0; row < count; row++ ) {
		for ( let col = 0; col < count; col++ ) {
			if ( qr.isDark( row, col ) ) {
				path += `M${ col + QUIET } ${ row + QUIET }h1v1h-1z`;
			}
		}
	}

	const svg = document.createElementNS( SVG_NS, 'svg' );
	svg.setAttribute( 'viewBox', `0 0 ${ total } ${ total }` );
	svg.setAttribute( 'width', String( size ) );
	svg.setAttribute( 'height', String( size ) );
	svg.setAttribute( 'shape-rendering', 'crispEdges' );
	svg.setAttribute( 'aria-hidden', 'true' );
	svg.setAttribute( 'focusable', 'false' );

	const bg = document.createElementNS( SVG_NS, 'rect' );
	bg.setAttribute( 'width', String( total ) );
	bg.setAttribute( 'height', String( total ) );
	bg.setAttribute( 'fill', '#fff' );
	svg.appendChild( bg );

	const dots = document.createElementNS( SVG_NS, 'path' );
	dots.setAttribute( 'd', path );
	dots.setAttribute( 'fill', '#000' );
	svg.appendChild( dots );

	element.replaceChildren( svg );

	return true;
}

/**
 * Draw every `[data-lwfw-qr]` element of the page.
 */
function renderAll() {
	document.querySelectorAll( '[data-lwfw-qr]' ).forEach( ( element ) => {
		render( element, element.getAttribute( 'data-lwfw-qr' ) );
	} );
}

window.lwFirewallQr = { render };

if ( document.readyState === 'loading' ) {
	document.addEventListener( 'DOMContentLoaded', renderAll );
} else {
	renderAll();
}
