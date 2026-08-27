# Changelog

## [1.5.3] - 2026-08-27

### Added
- Automatic bans can now be listed and lifted. Until now a banned IP could only wait out its TTL, be whitelisted, or be freed by flushing the whole storage backend — there was no way to answer "who is banned?" or to release one person on request
- `wp lw-firewall ban list|check <ip>|remove <ip>|clear` WP-CLI commands
- Automatic Bans table on the IP Rules tab: IP, reason, when it started, when it expires, and an Unblock button per row plus Unblock all
- `delete()` on the storage interface and all three backends (APCu, Redis, file), which the unban needs

### Fixed
- Lifting a ban now also clears the counters that produced it — rate-limit, failed-login, registration, password-reset and 404. Deleting only the ban key left those counters above their thresholds, so the very next request from that address would have been banned again immediately
- Bans now record why they happened (failed logins, registration spam, password-reset flood, rate limit), so an administrator can tell a locked-out user what tripped

### Changed
- Ban records are tracked in a non-autoloaded option alongside the storage key, because no storage backend can enumerate keys portably — the file backend hashes them, so an IP cannot be recovered from a filename. The storage key remains the sole authority on whether an IP is blocked; a listing is reconciled against it and marks entries the backend no longer holds as no longer enforced

## [1.5.2] - 2026-08-26

### Added
- Hungarian translations for everything added in 1.4.1, 1.5.0 and 1.5.1 — the Alerts tab, the password-reset sections of the Spam tab, every alert email (new administrator, account takeover, reset flood) and the messages shown on the lost-password form. 127 new strings; the catalogue is now complete at 319 of 319

### Changed
- Regenerated `languages/lw-firewall.pot` from the current source and dropped 31 obsolete entries from the Hungarian catalogue

## [1.5.1] - 2026-08-26

### Added
- Password reset flood protection, hooked on `lostpassword_post` — the one chokepoint both core's `retrieve_password()` and WooCommerce's own my-account implementation pass through, so the wp-login form and the WooCommerce "Lost your password?" form are covered by the same rules
- Three independent limits, because a reset flood has three shapes: per IP (one host hammering the form), **per target account** (many hosts flooding one person's inbox — invisible to per-IP limiting, and the shape used to harass a user or bury a real notification), and a site-wide hourly cap that protects the hosting mail quota and the sending domain's reputation
- Proof-of-render token and honeypot on the wp-login lost-password form, rejecting direct bot POSTs. Enforced only on wp-login.php, since other lost-password forms never render the token
- Optional auto-ban for IPs that trip the per-IP limit or fail the token check; the ban is written to the shared firewall ban store, so the MU-plugin worker blocks them before WordPress loads. Account and site-wide limits deliberately never ban — they say nothing about who happened to ask last
- Optional `reset_block_admins` hardening via the `allow_password_reset` filter: administrator accounts are taken out of the reset flow entirely, closing the "flood the admin inbox, then phish the reset link" path
- Optional email alert when a limit is reached, throttled to one message per limit per hour so the alert cannot become the flood it reports
- `wp lw-firewall reset status|on|off` WP-CLI command, with `--proof`, `--auto-ban`, `--alert` and `--block-admins` flags on `on`
- Single-use lost-password tokens: each rendered form may submit one request, so a bot cannot load the form once and replay that token for the rest of its lifetime. The single-use store is namespaced per form, because the token is derived from the issue timestamp alone — a registration and a lost-password form rendered in the same second share a token and would otherwise consume each other's entry
- Timing checks (minimum fill time, token lifetime) now have their own `reset_*` options instead of borrowing the registration ones, so the two forms are tunable independently and the Spam tab no longer shows registration fields governing reset behaviour
- New options: `reset_protect_enabled`, `reset_ip_max`, `reset_ip_window`, `reset_user_max`, `reset_user_window`, `reset_global_max`, `reset_proof_enabled`, `reset_min_fill_time`, `reset_token_max_age`, `reset_single_use`, `reset_auto_ban`, `reset_ban_duration`, `reset_block_admins`, `reset_alert_enabled`

### Changed
- Requests started by a user with `edit_users` or by WP-CLI bypass every reset limit, so the Users screen "Send password reset link" action and provisioning scripts keep working during a flood

## [1.5.0] - 2026-08-24

### Added
- New administrator alert: an email is sent whenever an account gains administrator privileges. WordPress hooks (`user_register`, `set_user_role`, `add_user_role`, `granted_super_admin`, `add_user_to_blog`) catch anything going through the user API — admin screens, plugins, REST, WP-CLI — and report the acting user and request IP
- Hourly reconciliation scan diffing the live administrator list against a stored snapshot, which is what catches accounts created by a direct database write, by code bypassing the WordPress user API, or while the plugin was inactive
- Alerts settings tab: recipient address (comma-separated list supported, falls back to the site admin email), scan toggle, run-scan and send-test buttons, and monitoring status including a warning when the last alert email failed to send
- `wp lw-firewall alerts status|scan|test|baseline` WP-CLI commands; `alerts scan` also lets sites with WP-Cron disabled drive the scan from a system cron
- Account takeover detection: the snapshot also fingerprints each administrator's username, email address and password (as a digest of the stored hash), and alerts when any of them changes on an account that already existed. Rewriting an admin's email address hands the attacker the password reset flow while the user ID stays the same, so watching for *new* accounts alone would never see it. Covered live by the `profile_update` and `wp_set_password` hooks, and by the same reconciliation scan for changes written straight to the database
- New options: `admin_alert_enabled`, `admin_alert_email`, `admin_alert_scan_enabled`, `admin_alert_changes` (overridable from wp-config.php like every other option)

## [1.4.1] - 2026-08-20

### Changed
- Tested up to WordPress 7.1.

## [1.4.0] - 2026-07-18

### Security
- Fixed a local file inclusion in geo blocking: blocked-country codes are validated before being used to build the cached CIDR include path
- Fixed .htaccess directive injection: blocked-country codes are validated before being written into RewriteCond rules
- Settings import now validates values (matching the settings form), so an untrusted import file can no longer inject unsafe options into the geo sinks above
- Fixed IPv4/IPv6 CIDR matching: a crafted IPv4 could match the first bytes of an IPv6 range, being trusted as Cloudflare (IP spoofing) or matching the wrong allow/deny entry. IPv6 allowlist entries now match regardless of notation
- Reworked the logged-in rate-limit exemption into a scoped, higher-limit bucket on REST/filter endpoints; a forged `wordpress_logged_in_` cookie can no longer disable rate limiting, and login/xmlrpc/cron stay fully throttled

### Fixed
- A blank entry in the bot list matched every request and 403'd the whole site
- File-based rate-limit counters now increment atomically under an exclusive lock, so concurrent floods no longer lose increments
- A Redis connection failure now fails open instead of fataling the front end
- Registration single-use tokens are enforced via an atomic counter (no reuse under concurrent submits)
- Hardened the filter rate-limit redirect against protocol-relative open redirects

### Changed
- Minimum PHP is now 8.2

### Added
- PHPStan level 5 static analysis and a PHPUnit test suite (with security regression tests) in CI

## [1.3.2] - 2026-06-13

### Changed
- Registration spam protection now defaults to enabled on new installs. It still only runs when registration is open (`users_can_register`); existing sites keep their saved setting

## [1.3.1] - 2026-06-13

### Added
- Registration spam protection for `wp-login.php?action=register`. A signed proof-of-render token (HMAC over `wp_salt('nonce')` + issue time) plus an optional honeypot reject bots — including WordPress-aware bots that POST directly without rendering the form. Token checks cover timing (too-fast submits), expiry, and optional single-use via the firewall storage backend
- New `RegisterTracker` counts rejected registrations per IP and bans repeat offenders through the shared ban store, so the MU-plugin worker blocks them before WordPress loads
- New Spam settings tab exposing the master toggle, honeypot, single-use, minimum fill time, token lifetime, ban threshold, and ban duration. Disabled by default; only active when "Anyone can register" is enabled; whitelisted IPs are never counted
- Complete Hungarian (hu_HU) translation covering all admin, settings, Spam tab, worker notice, and Site Manager strings

### Changed
- Regenerated the translation template (`languages/lw-firewall.pot`)

## [1.3.0] - 2026-06-07

### Added
- Brute-Force Login Protection (fail2ban style). A new `LoginTracker` hooks `wp_login_failed` and counts failed login attempts per IP; once the configured threshold is reached within the detection window the IP is banned via the shared firewall ban store, so the MU-plugin worker blocks every request from it before WordPress loads
- Three adjustable settings on the Protection tab: `login_max_attempts` (Failed Attempts), `login_lockout_window` (Detection Window), and `login_lockout_duration` (Ban Duration). Disabled by default; whitelisted IPs are never counted

## [1.2.7] - 2026-05-06

### Fixed
- MU-plugin worker (`worker/lw-firewall-worker.php`) now bumped in lockstep with the main plugin. The worker's runtime version guard silently disabled the firewall on sites that had a newer main plugin against an older worker; the missing bump in 1.2.6 left the firewall inactive after upgrade

### Internal
- Release workflow now fails the build when `LW_FIREWALL_VERSION`, `LW_FIREWALL_WORKER_VERSION`, and the worker's `@version` header drift apart, so a worker bump can never be skipped again

## [1.2.6] - 2026-04-30

### Changed
- Added missing `'default' => []` to top-level `input_schema` of `lw-firewall/get-log` so it can be invoked without arguments via the Abilities API

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
