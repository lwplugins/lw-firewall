/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { NumberRow, SwitchRow } from '../../components/Fields';
import Section from '../../components/Section';

const OFF = () => __( 'Off', 'lw-firewall' );

/**
 * Comment and WooCommerce product review protection.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store.
 */
export default function CommentSections( { store } ) {
	return (
		<Section
			title={ __( 'Comment & Review Protection', 'lw-firewall' ) }
			description={ __(
				'Stops bot comments and WooCommerce product reviews before they are stored, without a captcha. Works with every form built by comment_form(): classic and block themes, and both WooCommerce review forms. Administrators, editors of the post and whitelisted IPs are never checked.',
				'lw-firewall'
			) }
		>
			<SwitchRow
				title={ __( 'Enable Comment Protection', 'lw-firewall' ) }
				help={ __(
					'Checks every comment and review sent through the comment form (wp-comments-post.php). Comments added through the REST API, XML-RPC or the admin are not affected.',
					'lw-firewall'
				) }
				store={ store }
				name="comment_protect_enabled"
				onText={ __(
					'Block bot comments and product reviews',
					'lw-firewall'
				) }
				offText={ OFF() }
			/>
			<SwitchRow
				title={ __( 'Honeypot', 'lw-firewall' ) }
				help={ __(
					'A hidden field that visitors and screen readers never see. Bots that fill every field are rejected. A form without the field (for example a hand-built theme form) is never rejected because of it.',
					'lw-firewall'
				) }
				store={ store }
				name="comment_honeypot"
				onText={ __( 'Add a hidden honeypot field', 'lw-firewall' ) }
				offText={ OFF() }
			/>
			<SwitchRow
				title={ __( 'Signed Form Token', 'lw-firewall' ) }
				help={ __(
					'Rejects comments posted straight to wp-comments-post.php without loading the page. If your theme builds its comment form without comment_form(), every comment is rejected: test a comment after turning this on.',
					'lw-firewall'
				) }
				store={ store }
				name="comment_token_enabled"
				onText={ __(
					'Require a token from the rendered form',
					'lw-firewall'
				) }
				offText={ OFF() }
			/>
			<NumberRow
				title={ __( 'Minimum Fill Time', 'lw-firewall' ) }
				help={ __(
					'Reject comments sent faster than this many seconds after the page was generated.',
					'lw-firewall'
				) }
				store={ store }
				name="comment_min_fill_time"
				seconds
			/>
			<NumberRow
				title={ __( 'Token Lifetime', 'lw-firewall' ) }
				help={ __(
					'How long a rendered comment form stays valid, in seconds (86400 = 1 day). Cached pages are safe: when a visitor starts typing into a form older than half this time, a fresh token is fetched in the background. Tokens are never single-use here, because a page cache shows the same form to everyone.',
					'lw-firewall'
				) }
				store={ store }
				name="comment_token_max_age"
				seconds
			/>
		</Section>
	);
}
