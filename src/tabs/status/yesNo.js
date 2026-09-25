/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import StatusBadge from '../../components/StatusBadge';

/**
 * Yes / No pill; `good` says which answer is the healthy one. Unknown (null)
 * renders a dash.
 *
 * @param {boolean|null} value Answer.
 * @param {boolean}      good  Healthy answer.
 * @return {Element} Badge.
 */
export default function yesNo( value, good = true ) {
	if ( value === null || value === undefined ) {
		return '—';
	}
	return (
		<StatusBadge status={ value === good ? 'ok' : 'warning' }>
			{ value ? __( 'Yes', 'lw-firewall' ) : __( 'No', 'lw-firewall' ) }
		</StatusBadge>
	);
}
