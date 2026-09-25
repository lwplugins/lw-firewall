/**
 * WordPress dependencies
 */
import { Button } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import StatusBadge from '../../components/StatusBadge';
import { ago, datetime, until } from '../../data/format';

/**
 * Username locks (1.6.0): each row can be unlocked on its own; "Unlock all"
 * asks first (through the shared confirm).
 *
 * @param {Object} props
 * @param {Array}  props.locks toBans().userLocks.
 * @param {Object} props.unban useUnban() API.
 */
export default function UserLocks( { locks, unban } ) {
	if ( ! locks.length ) {
		return null;
	}
	return (
		<div className="lw-admin-stack lw-admin-userlocks">
			<div className="lw-admin-inline lw-admin-userlocks__head">
				<span className="lw-admin-label">
					{ __( 'Locked usernames', 'lw-firewall' ) }
				</span>
				{ locks.length > 1 && (
					<Button
						size="compact"
						variant="tertiary"
						onClick={ () =>
							unban.ask( { users: locks.map( ( l ) => l.key ) } )
						}
					>
						{ __( 'Unlock all usernames', 'lw-firewall' ) }
					</Button>
				) }
			</div>
			<table className="lw-admin-mini">
				<thead>
					<tr>
						<th>{ __( 'Username', 'lw-firewall' ) }</th>
						<th>{ __( 'Locked', 'lw-firewall' ) }</th>
						<th>{ __( 'Expires', 'lw-firewall' ) }</th>
						<th>{ __( 'Status', 'lw-firewall' ) }</th>
						<th>
							<span className="screen-reader-text">
								{ __( 'Actions', 'lw-firewall' ) }
							</span>
						</th>
					</tr>
				</thead>
				<tbody>
					{ locks.map( ( lock ) => (
						<tr key={ lock.id }>
							<td>
								<span className="lw-admin-inline">
									<StatusBadge status="info">
										{ __( 'Username', 'lw-firewall' ) }
									</StatusBadge>
									<code>{ lock.user || lock.key }</code>
								</span>
							</td>
							<td>
								{ ago( lock.time ) }
								<br />
								<span className="lw-admin-hint">
									{ datetime( lock.time ) }
								</span>
							</td>
							<td>
								{ until( lock.expires ) }
								<br />
								<span className="lw-admin-hint">
									{ datetime( lock.expires ) }
								</span>
							</td>
							<td>
								<StatusBadge
									status={ lock.active ? 'critical' : 'idle' }
								>
									{ lock.active
										? __( 'Enforced', 'lw-firewall' )
										: __( 'Tracked only', 'lw-firewall' ) }
								</StatusBadge>
							</td>
							<td>
								<Button
									size="compact"
									variant="secondary"
									isBusy={ unban.busy === lock.id }
									disabled={ !! unban.busy }
									accessibleWhenDisabled
									onClick={ () =>
										unban.run(
											{ users: [ lock.key ] },
											lock.id
										)
									}
								>
									{ __( 'Unlock', 'lw-firewall' ) }
								</Button>
							</td>
						</tr>
					) ) }
				</tbody>
			</table>
		</div>
	);
}
