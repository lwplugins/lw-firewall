# Changelog

## [1.2.5] - 2026-04-30

### Added
- WP-CLI: `config set` now coerces values to match the option's stored type. List-typed options (`filter_params`, `blocked_bots`, `ip_whitelist`, `ip_blacklist`, `blocked_countries`) accept comma- or newline-separated entries and are stored as arrays
- WP-CLI: `config list --format=json` (and `yaml`) preserve the stored types instead of stringifying everything; the `table` view renders arrays as `[a, b, c]` so lists are visually distinct from strings
- WP-CLI: `config get <key> [--format=var_export|json|yaml]` for inspecting a single setting with the type preserved
- WP-CLI: new `config-items` subcommand with `add` / `remove` for incremental edits to list-typed options without rewriting the whole list

### Fixed
- Defensive normalisation: list-typed options accidentally saved as a single string with newlines or commas (via `wp option update`, manual SQL, or legacy data) are now coerced to arrays on read. Without this the worker would `(array)` the string into a single-element list and only honour the first entry, silently dropping the rest of the rate-limit prefixes
- `Options::save()` no longer assigns the unused `$default_value` loop variable; iterates `array_keys()` instead
- Filter Parameters help text wrongly listed the default as `filter_, query_type_` — the actual default has been `filter_|30, query_type_|30` since 1.2.0
- Tightened admin descriptions for Enable Firewall (master switch, not just filter requests), Rate Limit (applies to all rate-checked endpoints), Rate Limit Action (302 redirect strips query params; 429 sends Retry-After), IP Whitelist/Blacklist (CIDR/IPv6 supported), and Blocked User-Agents (case-insensitive substring match)

### Internal
- ConfigCommand split into `ConfigCommand` (list/get/set/reset) + `ConfigItemsCommand` (add/remove) sharing a `ConfigOpsTrait`, keeping each class under the 200-line limit
- New `ValueCaster` utility centralises raw-input → typed-value casting and value → display-string rendering for the CLI

## [1.2.4] - 2026-04-26

### Added
- `LW_FIREWALL_DISABLE_WORKER` wp-config constant — emergency kill switch for the MU-plugin worker
- Worker auto-reinstall on `upgrader_process_complete` to close the post-update race condition
- Status tab now shows mu-plugins directory writability and the last install attempt result
- Activator records the outcome of every install attempt (writable check, copy result) in a transient

### Changed
- If the MU-plugin worker is missing or its version does not match the plugin, runtime protection is disabled and a detailed admin notice is shown until the worker is restored — fail loud, not half-on
- WorkerNotice replaces the previous single-line install notice with actionable diagnostics

### Fixed
- Worker is now wrapped in a top-level try/catch and verifies every required class file before running — prevents fatal errors when plugin files are partially missing
- Worker refuses to run when its version drifts from the main plugin (prevents fatals during plugin updates when old worker meets new classes)
- Worker bails silently on PHP < 8.1 instead of throwing a fatal

## [1.2.3] - 2026-03-23

### Fixed
- Worker version synced to match plugin version (was stuck at 1.1.9)
- Admin notice when MU-plugin worker installation fails (instead of silent failure)

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
