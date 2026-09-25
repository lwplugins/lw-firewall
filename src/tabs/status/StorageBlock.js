/**
 * WordPress dependencies
 */
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import KeyValue from '../../components/KeyValue';
import Section from '../../components/Section';
import StatusBadge from '../../components/StatusBadge';
import yesNo from './yesNo';

/**
 * Active storage backend + the live set/get/delete probe (a failing backend
 * fails open silently otherwise) + the file cache directory.
 *
 * @param {Object} props
 * @param {Object} props.storage Status storage block.
 */
export default function StorageBlock( { storage } ) {
	return (
		<Section
			title={ __( 'Active Storage', 'lw-firewall' ) }
			description={ __(
				'Storage backend used for rate-limit counters.',
				'lw-firewall'
			) }
		>
			<KeyValue
				rows={ [
					{
						label: __( 'Backend', 'lw-firewall' ),
						value: <code>{ storage.active || '—' }</code>,
					},
					storage.backend && {
						label: __( 'Resolved backend', 'lw-firewall' ),
						value: <code>{ storage.backend }</code>,
					},
					storage.preference && {
						label: __( 'Configured', 'lw-firewall' ),
						value: <code>{ storage.preference }</code>,
					},
					storage.probe && {
						label: __( 'Round-trip test', 'lw-firewall' ),
						help: __(
							'Writes, reads and deletes a test value.',
							'lw-firewall'
						),
						value: (
							<span className="lw-admin-stack">
								<StatusBadge
									status={
										storage.probe.ok ? 'ok' : 'critical'
									}
								>
									{ storage.probe.ok
										? __( 'Working', 'lw-firewall' )
										: __( 'Failed', 'lw-firewall' ) }
								</StatusBadge>
								{ storage.probe.message && (
									<span>{ storage.probe.message }</span>
								) }
							</span>
						),
					},
					storage.fileDir && {
						label: __( 'Cache directory writable', 'lw-firewall' ),
						help: __( 'Used by the File backend.', 'lw-firewall' ),
						value: (
							<span className="lw-admin-stack">
								{ yesNo( storage.fileDirWritable ) }
								<code className="lw-admin-code">
									{ storage.fileDir }
								</code>
							</span>
						),
					},
				] }
			/>
		</Section>
	);
}
