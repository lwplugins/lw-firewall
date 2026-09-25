/**
 * WordPress dependencies
 */
import { dateI18n, humanTimeDiff } from '@wordpress/date';
import { __ } from '@wordpress/i18n';

const MS = 1000;
const now = () => Math.floor( Date.now() / MS );

/**
 * Relative past time in the site locale ("12 minutes ago"); "unknown" for 0.
 * humanTimeDiff carries WordPress' own translated "ago" / "from now".
 *
 * @param {number} ts Unix seconds.
 * @return {string} Label.
 */
export const ago = ( ts ) =>
	ts ? humanTimeDiff( ts * MS ) : __( 'unknown', 'lw-firewall' );

/**
 * Relative future time ("40 minutes from now"); "expired" once past.
 *
 * @param {number} ts Unix seconds.
 * @return {string} Label.
 */
export const until = ( ts ) =>
	ts && ts > now()
		? humanTimeDiff( ts * MS )
		: __( 'expired', 'lw-firewall' );

/**
 * "Y-m-d H:i" in the site timezone; "—" for 0.
 *
 * @param {number} ts Unix seconds.
 * @return {string} Date.
 */
export const datetime = ( ts ) =>
	ts ? dateI18n( 'Y-m-d H:i', ts * MS ) : '—';

/**
 * An age in seconds as relative past time.
 *
 * @param {number} seconds Age.
 * @return {string} Label.
 */
export const age = ( seconds ) => ago( now() - Number( seconds ) );
