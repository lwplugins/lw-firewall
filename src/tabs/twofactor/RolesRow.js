/**
 * WordPress dependencies
 */
import { CheckboxControl } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

/**
 * Internal dependencies
 */
import { fieldOf } from '../../components/Fields';
import SettingRow from '../../components/SettingRow';

/**
 * Which roles must use a second factor: one checkbox per site role.
 *
 * @param {Object} props
 * @param {Object} props.store Settings store.
 */
export default function RolesRow( { store } ) {
	const name = 'twofa_required_roles';
	const field = fieldOf( store, name );
	const selected = store.data.options[ name ] || [];
	const roles = store.data.meta.roles;

	const toggle = ( role, on ) =>
		store.set(
			name,
			on
				? [ ...selected.filter( ( r ) => r !== role ), role ]
				: selected.filter( ( r ) => r !== role )
		);

	return (
		<SettingRow
			title={ __( 'Required Roles', 'lw-firewall' ) }
			help={ __(
				'Users in these roles must set up a second factor. Until the grace period ends they only get a reminder; after that they are taken to the setup page at login instead of being locked out. Everyone else can opt in on their profile.',
				'lw-firewall'
			) }
			stacked
			{ ...field }
		>
			<div
				className="lw-fw-twofa__roles"
				role="group"
				aria-label={ __( 'Required Roles', 'lw-firewall' ) }
			>
				{ roles.map( ( { value, label } ) => (
					<CheckboxControl
						key={ value }
						__nextHasNoMarginBottom
						label={ label }
						checked={ selected.includes( value ) }
						disabled={ !! field.locked }
						onChange={ ( on ) => toggle( value, on ) }
					/>
				) ) }
			</div>
		</SettingRow>
	);
}
