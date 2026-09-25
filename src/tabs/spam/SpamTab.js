/**
 * Internal dependencies
 */
import Registration from './RegistrationSections';
import { ResetFlood, ResetHardening } from './ResetSections';

export default function SpamTab( { store } ) {
	return (
		<>
			<Registration
				store={ store }
				registrationOpen={ store.data.meta.usersCanRegister }
			/>
			<ResetFlood store={ store } />
			<ResetHardening store={ store } />
		</>
	);
}
