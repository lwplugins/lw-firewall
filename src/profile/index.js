/**
 * LW Firewall: two-factor section of the profile screens (build/profile.js).
 * Mounts into the container ProfileSection prints.
 */
/**
 * WordPress dependencies
 */
import { createRoot } from '@wordpress/element';

/**
 * Internal dependencies
 */
import AdminReset from './AdminReset';
import SelfService from './SelfService';
import './profile.scss';

const root = document.getElementById( 'lw-firewall-2fa' );

if ( root ) {
	let config = {};
	try {
		config = JSON.parse( root.getAttribute( 'data-config' ) || '{}' );
	} catch {
		config = {};
	}

	createRoot( root ).render(
		config.self ? (
			<SelfService passkeysAvailable={ !! config.passkeys } />
		) : (
			<AdminReset userId={ Number( config.userId ) } />
		)
	);
}
