# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.2.2] - 2026-03-22

### Added
- LW Site Manager integration - firewall abilities for AI agents
- `lw-firewall/get-options` ability - get firewall settings
- `lw-firewall/get-log` ability - get firewall log entries
- `lw-firewall/list-blocked` ability - list blocked IPs
- `lw-firewall/block-ip` ability - block an IP address
- `lw-firewall/unblock-ip` ability - unblock an IP address

## [1.2.1]

### Added
- Sync `.htaccess` geo blocking rules on plugin activation
- Geo blocking enabled by default with pre-defined blocked countries (CN, RU, IN, VN, ID, BD)

## [1.2.0]

### Added
- Import/Export settings tab - export all firewall settings as JSON, import on another site
- JSON validation: only known setting keys are accepted, missing keys filled with defaults

## [1.1.9]

### Added
- `.htaccess` CF-IPCountry rewrite - Apache-level geo blocking before PHP loads
- Auto-sync `.htaccess` on settings save, WP-CLI add/remove, and plugin deactivation
- WP-CLI `geo` command: `list`, `add`, `remove`, `update` blocked countries
- Geo blocking status shown in `wp lw-firewall status`

## [1.1.8]

### Added
- Geo Blocking - block visitors by country code
- Cloudflare `CF-IPCountry` header support (instant, zero-cost)
- CIDR-based fallback for non-Cloudflare setups (weekly auto-update from ipdeny.com)
- New Geo Blocking tab in admin settings
- Configurable block action (403 Forbidden or redirect to homepage)
- Manual CIDR list update button

## [1.1.7]

### Fixed
- Redis storage: skip Redis backend when authentication is required (prevents NOAUTH fatal error)

## [1.1.6]

### Added
- Per-filter-param rate limit override (e.g. `filter_|30` limits filter requests to 30/window)

### Changed
- Bot blocking now applies to all requests, not just filter URLs
- Blocked bots no longer bypass protection on regular pages, admin-ajax, or REST API
- Custom limit uses the lowest value when multiple filter params match

## [1.1.5]

### Fixed
- Minor fix

## [1.1.4]

### Added
- Hash-based tab navigation on settings page
- New block-brick-fire icon
- Updated ParentPage with SVG icon support from registry
- Suppressed expected PHPCS warnings for CLI and FileStorage

## [1.1.3]

### Added
- Automatic server/localhost IP whitelisting (127.0.0.1, ::1, SERVER_ADDR, domain IP)
- Cloudflare IPv6 ranges to IP detection
- Full IPv6 support for rate limiting, whitelist, blacklist, and CIDR matching

## [1.1.2]

### Fixed
- Release ZIP folder structure

## [1.1.1]

### Fixed
- Plugin description - general WordPress firewall, not WooCommerce-specific

### Changed
- Updated settings page title to "Lightweight Firewall"

## [1.1.0]

### Added
- `wp-login.php` brute-force protection
- `wp-cron.php` DDoS protection
- `xmlrpc.php` DDoS protection
- REST API rate limiting
- 404 flood detection and blocking
- IP whitelist and blacklist with CIDR support
- Auto-ban with escalating violations
- Security HTTP headers with detailed explanations
- Protection tab for endpoint toggles
- IP Rules tab for whitelist/blacklist
- Security tab for HTTP headers
- `wp-config.php` constant overrides
- WP-CLI `ip` command (`list`/`add`/`remove` whitelist/blacklist)
- Worker version tracking with auto-update on mismatch
- Hungarian (hu_HU) translation

### Changed
- Updated admin UI with 7 settings tabs
- Updated WP-CLI status command with all new settings

## [1.0.0]

### Added
- Initial release
