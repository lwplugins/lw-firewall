/**
 * WordPress dependencies
 */
import { Icon, caution, check, info } from '@wordpress/icons';

const ICONS = { ok: check, error: caution, warning: caution, info };

/**
 * Inline outcome of an action (unban, scan, import…): icon + message +
 * optional detail lines. Errors are announced assertively.
 *
 * @param {Object}  props
 * @param {string}  props.tone     ok|error|warning|info.
 * @param {string}  props.message  Main line.
 * @param {Array}   props.details  Extra lines (strings or nodes).
 * @param {Element} props.children Extra content.
 */
export default function ResultBox( {
	tone = 'info',
	message,
	details = [],
	children,
} ) {
	return (
		<div
			className={ `lw-admin-result is-${ tone }` }
			role={ tone === 'error' ? 'alert' : 'status' }
		>
			<Icon icon={ ICONS[ tone ] || info } size={ 20 } />
			<div className="lw-admin-result__body">
				{ message && <p>{ message }</p> }
				{ details.length > 0 && (
					<ul>
						{ details.map( ( line, index ) => (
							<li key={ index }>{ line }</li>
						) ) }
					</ul>
				) }
				{ children }
			</div>
		</div>
	);
}
