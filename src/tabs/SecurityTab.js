/**
 * WordPress dependencies
 */
import { Icon, ToggleControl } from '@wordpress/components';
import { __, sprintf } from '@wordpress/i18n';
import { file, layout, link, video, shield } from '@wordpress/icons';

/**
 * Internal dependencies
 */
import { fieldOf } from '../components/Fields';
import Section from '../components/Section';
import StatusBadge from '../components/StatusBadge';

/**
 * What each header the server can send protects against. Headers the server
 * sends but this map does not know are still listed, without the text.
 */
const explain = () => ( {
	'X-Content-Type-Options': {
		icon: file,
		protects: __( 'Against MIME sniffing', 'lw-firewall' ),
		text: __(
			'The browser does not guess a file’s type, so a text file can never run as JavaScript.',
			'lw-firewall'
		),
	},
	'X-Frame-Options': {
		icon: layout,
		protects: __( 'Against clickjacking', 'lw-firewall' ),
		text: __(
			'Other domains cannot embed your site in an iframe, so visitors cannot be tricked into clicking hidden elements.',
			'lw-firewall'
		),
	},
	'Referrer-Policy': {
		icon: link,
		protects: __( 'Against URL leaks', 'lw-firewall' ),
		text: __(
			'Other sites only see your domain; the full URL, which may contain sensitive paths, stays on your site.',
			'lw-firewall'
		),
	},
	'Permissions-Policy': {
		icon: video,
		protects: __( 'Against device access', 'lw-firewall' ),
		text: __(
			'Turns off the camera, microphone and geolocation, so even a compromised third-party script cannot ask for them.',
			'lw-firewall'
		),
	},
} );

/**
 * Security tab: one switch for the headers, and every header the server
 * sends with its value and what it protects against.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store.
 */
export default function SecurityTab( { store } ) {
	const texts = explain();
	// Exactly the headers the server sends (meta.server.security_headers).
	const headers = store.data.meta.securityHeaders;
	const field = fieldOf( store, 'security_headers' );
	const on = !! store.data.options.security_headers;

	const actions = (
		<div className="lw-admin-inline lw-fw-headers__switch">
			<StatusBadge status={ on ? 'ok' : 'idle' }>
				{ on
					? sprintf(
							/* translators: %d: number of security headers sent. */
							__( 'All %d sent', 'lw-firewall' ),
							headers.length
						)
					: __( 'Not sent', 'lw-firewall' ) }
			</StatusBadge>
			<ToggleControl
				__nextHasNoMarginBottom
				label={
					on ? __( 'On', 'lw-firewall' ) : __( 'Off', 'lw-firewall' )
				}
				checked={ on }
				disabled={ !! field.locked }
				onChange={ ( value ) => store.set( 'security_headers', value ) }
			/>
		</div>
	);

	return (
		<Section
			title={ __( 'Security Headers', 'lw-firewall' ) }
			description={ sprintf(
				/* translators: %d: number of security headers. */
				__(
					'%d HTTP response headers the firewall adds to every page.',
					'lw-firewall'
				),
				headers.length
			) }
			actions={ actions }
		>
			{ field.locked && (
				<p className="lw-fw-headers__locked">
					{ sprintf(
						/* translators: %s: PHP constant name. */
						__( 'Set in wp-config.php (%s).', 'lw-firewall' ),
						field.locked
					) }
				</p>
			) }
			<ul className={ `lw-fw-headers${ on ? '' : ' is-off' }` }>
				{ headers.map( ( { name, value } ) => {
					const known = texts[ name ];
					return (
						<li key={ name } className="lw-fw-headers__row">
							<span
								className="lw-fw-headers__icon"
								aria-hidden="true"
							>
								<Icon
									icon={ known ? known.icon : shield }
									size={ 20 }
								/>
							</span>
							<div className="lw-fw-headers__main">
								<code className="lw-fw-headers__name">
									{ name }
								</code>
								<code className="lw-fw-headers__value">
									{ value }
								</code>
							</div>
							{ known && (
								<span className="lw-fw-headers__protects">
									{ known.protects }
								</span>
							) }
							{ known && (
								<p className="lw-fw-headers__text">
									{ known.text }
								</p>
							) }
						</li>
					);
				} ) }
			</ul>
		</Section>
	);
}
