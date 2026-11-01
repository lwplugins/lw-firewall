/**
 * WordPress dependencies
 */
import { useCallback } from '@wordpress/element';

/**
 * Internal dependencies
 */
import FormSkeleton from './components/FormSkeleton';
import LoadError from './components/LoadError';
import Notices from './components/Notices';
import { api } from './data/api';
import useRemote from './data/useRemote';
import useSettingsStore from './data/useSettingsStore';
import Footer from './shell/Footer';
import navMeta from './shell/navMeta';
import SideNav from './shell/SideNav';
import TopBar from './shell/TopBar';
import { TABS } from './shell/tabs';
import useSaveShortcut from './shell/useSaveShortcut';
import useTab from './shell/useTab';
import useUnsavedWarning from './shell/useUnsavedWarning';
import QuickSearch from './quick-search';
import AlertsTab from './tabs/alerts/AlertsTab';
import BotsTab from './tabs/BotsTab';
import GeneralTab from './tabs/GeneralTab';
import GeoTab from './tabs/geo/GeoTab';
import ImportExportTab from './tabs/importexport/ImportExportTab';
import IpRulesTab from './tabs/iprules/IpRulesTab';
import LogsTab from './tabs/logs/LogsTab';
import ProtectionTab from './tabs/ProtectionTab';
import SecurityTab from './tabs/SecurityTab';
import SpamTab from './tabs/spam/SpamTab';
import StatusTab from './tabs/status/StatusTab';
import TwoFactorTab from './tabs/twofactor/TwoFactorTab';

const VIEWS = {
	general: GeneralTab,
	protection: ProtectionTab,
	spam: SpamTab,
	bots: BotsTab,
	'ip-rules': IpRulesTab,
	geo: GeoTab,
	security: SecurityTab,
	'two-factor': TwoFactorTab,
	alerts: AlertsTab,
	status: StatusTab,
	logs: LogsTab,
	'import-export': ImportExportTab,
};

// Tabs the quick search renders off screen: they build only from the loaded
// options. IP Rules (bans list), Two-Factor (summary), Status, Logs and
// Import / Export fetch or only report, so they are found by name only.
const SEARCH_TABS = [
	'general',
	'protection',
	'spam',
	'bots',
	'geo',
	'security',
	'alerts',
];

// Stands in for the status report while indexing (no request, no data).
const NO_STATUS = { data: null, error: null, reload: () => {} };

// Classic links (?page=lw-firewall&tab=status, WorkerNotice) open that tab.
const INITIAL_TAB =
	new URLSearchParams( window.location.search ).get( 'tab' ) || 'general';

/**
 * Shell + one options store shared by every tab (partial saves) + the status
 * report (warnings badge in the nav, Status and Alerts tabs).
 */
export default function App() {
	const store = useSettingsStore();
	const loadStatus = useCallback( () => api.status(), [] );
	const status = useRemote( loadStatus );
	const tab = useTab(
		TABS.map( ( t ) => t.id ),
		INITIAL_TAB
	);
	const current = TABS.find( ( t ) => t.id === tab ) || TABS[ 0 ];
	const View = VIEWS[ current.id ];

	useUnsavedWarning( store.hasEdits );
	useSaveShortcut( store.save, store.hasEdits && ! store.isSaving );

	// The quick search indexes the settings tabs (read-only renders of the
	// loaded options).
	const searchPages = useCallback(
		() =>
			store.data
				? TABS.filter( ( t ) => SEARCH_TABS.includes( t.id ) ).map(
						( t ) => {
							const Tab = VIEWS[ t.id ];
							return {
								tab: t,
								element: (
									<Tab store={ store } status={ NO_STATUS } />
								),
							};
						}
					)
				: null,
		[ store ]
	);

	let content;
	if ( store.error ) {
		content = (
			<LoadError message={ store.error } onRetry={ store.reload } />
		);
	} else if ( store.isLoading ) {
		content = <FormSkeleton />;
	} else {
		content = <View store={ store } status={ status } />;
	}

	return (
		<>
			<div className="lw-admin-shell">
				<SideNav
					tabs={ TABS }
					current={ current.id }
					meta={ navMeta( store.errors, status.data ) }
					docsUrl={ store.data?.meta.docsUrl }
					search={
						<QuickSearch
							tabs={ TABS }
							pages={ searchPages }
							storageKey="lw-firewall-quick-search"
						/>
					}
				/>
				<div className="lw-admin-main">
					<TopBar
						title={ current.title }
						store={ current.save && store.data ? store : null }
					/>
					<main className="lw-admin-scroll">
						<div className="lw-admin-content">{ content }</div>
					</main>
					<Footer />
				</div>
			</div>
			<Notices />
		</>
	);
}
