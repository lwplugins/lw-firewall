/**
 * Server-provided boot data (SettingsPage inline script `window.lwFirewall`).
 */
const boot = window.lwFirewall || {};

export const VERSION = boot.version || '';
export const NAMESPACE = boot.namespace || 'lw-firewall/v1';
export const DOCS_URL =
	boot.docsUrl || 'https://lwplugins.com/docs/lw-firewall/';
