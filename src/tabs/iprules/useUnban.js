/**
 * WordPress dependencies
 */
import { useDispatch } from '@wordpress/data';
import { useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { store as noticesStore } from '@wordpress/notices';

/**
 * Internal dependencies
 */
import ResultBox from '../../components/ResultBox';
import { api, errorMessage } from '../../data/api';

/**
 * Run one unban request. Targets: { ips }, { users } (lock keys) or 'all'.
 *
 * @param {Object|string} target Target.
 * @return {Promise} toUnbanResult().
 */
const request = ( target ) => {
	if ( target === 'all' ) {
		return api.unbanAll();
	}
	return target.users
		? api.unbanUsers( target.users )
		: api.unbanIps( target.ips );
};

/**
 * Unblock flow: single rows run at once; bulk and "all" wait for the in-page
 * confirm. The server answers per address / username and returns the fresh
 * list; every failure is listed with its own message.
 *
 * @param {Function} setBans Replace the list with the returned payload.
 * @param {Function} reload  Refetch (when no payload came back).
 * @param {Function} onDone  After a request (clear the selection).
 * @return {Object} { run, ask, confirm, cancel, pending, busy, result }.
 */
export default function useUnban( setBans, reload, onDone ) {
	const [ pending, setPending ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ failures, setFailures ] = useState( null );
	const { createSuccessNotice, createErrorNotice } =
		useDispatch( noticesStore );

	const run = async ( target, busyId = 'bulk' ) => {
		setBusy( busyId );
		setFailures( null );
		try {
			const { results, bans } = await request( target );
			const failed = results.filter( ( r ) => ! r.ok );
			const lifted = results.length - failed.length;
			if ( lifted > 0 ) {
				createSuccessNotice(
					target === 'all' && ! failed.length
						? __(
								'All tracked bans lifted and their counters cleared.',
								'lw-firewall'
							)
						: sprintf(
								/* translators: %d: number of lifted bans or username locks. */
								_n(
									'%d ban lifted. Its counters were cleared too, so the next request starts from zero.',
									'%d bans lifted. Their counters were cleared too, so the next request starts from zero.',
									lifted,
									'lw-firewall'
								),
								lifted
							),
					{ type: 'snackbar' }
				);
			}
			setFailures( failed.length ? failed : null );
			onDone();
			if ( bans ) {
				setBans( bans );
			} else {
				reload();
			}
		} catch ( e ) {
			createErrorNotice( errorMessage( e ), { type: 'snackbar' } );
			reload();
		}
		setBusy( '' );
	};

	return {
		run,
		ask: setPending,
		pending,
		busy,
		cancel: () => setPending( null ),
		confirm: () => {
			const target = pending;
			setPending( null );
			run( target );
		},
		result: failures && (
			<ResultBox
				tone="error"
				message={ sprintf(
					/* translators: %d: number of bans that could not be lifted. */
					_n(
						'%d ban could not be lifted:',
						'%d bans could not be lifted:',
						failures.length,
						'lw-firewall'
					),
					failures.length
				) }
				details={ failures.map( ( f ) => (
					<>
						<code>{ f.label }</code> { f.message }
					</>
				) ) }
			/>
		),
	};
}
