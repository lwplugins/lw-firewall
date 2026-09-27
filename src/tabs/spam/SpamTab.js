/**
 * Internal dependencies
 */
import AutoBanSection from './AutoBanSection';
import CommentSections from './CommentSections';
import Registration from './RegistrationSections';
import { ResetFlood, ResetHardening } from './ResetSections';

export default function SpamTab( { store } ) {
	return (
		<>
			<Registration
				store={ store }
				registrationOpen={ store.data.meta.usersCanRegister }
			/>
			<CommentSections store={ store } />
			<AutoBanSection store={ store } />
			<ResetFlood store={ store } />
			<ResetHardening store={ store } />
		</>
	);
}
