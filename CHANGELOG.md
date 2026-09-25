# Changelog

## [1.6.0] - 2026-09-25

### Added
- New settings screen built with WordPress components: side navigation for the eleven sections, a top bar with Save/Discard and a Cmd/Ctrl+S shortcut, loading skeletons and a mobile layout. Only changed settings are saved; an invalid value is shown next to its field and nothing is saved.
- Every action has its own button and never saves unsaved edits: unblock (per address, selected or all, with per-address results), manual ban, clear log, reinstall worker, update CIDR lists, run the administrator scan, send a test email, import and export.
- Per-username login lockout: after 10 failed logins within the detection window, from any IP, the account is locked for 15 minutes, correct password included. Failures count under the account's real login, so email logins and Unicode look-alike spellings add up to the same lock. Whitelisted IPs bypass it. Lift a lock from the Bans list or with `wp lw-firewall user-lock remove <username|email>` / `clear`. `login_user_limit_enabled` defaults to on, so sites that already have brute-force login protection on get username locking after the update.
- The Status tab shows how the firewall sees your IP (REMOTE_ADDR, forwarded headers, trusted proxy match, Cloudflare, routable) (#6), tests the storage backend with a write/read/delete round trip, checks the cache directory, shows geo list freshness per country and alert state, and lists warnings with a badge in the navigation.
- The ban list shows the storage backend in use, IPv6 /64 and legacy entries and username locks; administrators can ban an address manually.
- The log view has reason labels, a reason filter, search and paging.
- Admin REST API under `lw-firewall/v1/admin/` for users with `manage_options`.
- Violet accent for the admin and the plugin logo; Hungarian translation of the whole new interface.

### Changed
- XML-RPC rate limiting is on by default for new installs only. Existing sites, including multisite subsites without their own settings, keep their current setting.
- The Security tab lists exactly the headers that are sent, with what each one protects against.
- The classic settings screen and its stylesheet and script were removed.

### Fixed
- "Update CIDR lists" works and reports each country for IPv4 and IPv6.
- Country codes must be ISO 3166-1 codes: "Germany" is rejected instead of being saved as GE, and "CN, RU" on one line keeps both.
- IP whitelist, blacklist and trusted proxy entries are validated, and invalid entries are reported.
- An empty Filter Parameters list resets to `filter_|30, query_type_|30`, limits included.
- Invalid alert email addresses are reported instead of being dropped silently.
- Settings pinned in wp-config.php are never written to the database by the admin, the import or WP-CLI.
- Import keeps settings missing from the file, reads "false" as off, validates every value and reports each setting.
- The number limits in the admin match the server limits, so a value set through WP-CLI can no longer block saving the form.
- "Unblock every banned address" reports each address, and a ban the storage refuses to lift stays listed.
- The administrator scan no longer says "clean" when alerts are off, or "email sent" when the mail was queued.
- A refusal caused by a locked username no longer counts against the visitor's IP, so an owner retrying with the right password cannot get their own IP banned.
- The admin can no longer ban the address they are currently using.
- Worker install errors are shown as sentences, not codes, and the plugin's own warnings (Status, Alerts, import results) are visible again.
- The admin screen no longer depends on the translated parent-menu name to load.
- WP-CLI `config set` rejects invalid values, and `config reset` leaves wp-config.php-pinned settings alone.
- List settings are capped at 5000 entries, and settings requests at 256 KB.

## [1.5.10] - 2026-09-25

### Fixed
- Notices from themes and other plugins (for example a theme's purchase-code or recommended-plugins notice) could show on the LW Firewall screen. They are now kept off every LW Plugins screen, whatever their markup
- LW Firewall's own warnings and messages on its settings tabs (the Status tab's IP and worker warnings, the Alerts tab's pending-queue and mail-error warnings, and the import result) were hidden. They show again

## [1.5.9] - 2026-09-25

### Security
- **IPv6 clients were counted and banned per address, so an attacker rotating addresses inside one /64 was never limited.** Every rate, login, 404, registration and password-reset counter, and every ban, now covers the whole /64. The ban list shows the /64; unblocking any address inside it, or the /64 itself, lifts the ban (admin and `wp lw-firewall ban remove`/`check`). Bans created by 1.5.8 are still enforced until they expire and can still be lifted. IP whitelist and blacklist entries match exactly as written, as before
- **`/wp-login.php/x`, `/xmlrpc.php/x`, `/wp-cron.php/x` and case variants such as `/XMLRPC.php` escaped the login, XML-RPC and cron limits**, although the server still runs the script. The endpoint is now matched as a whole path segment, ignoring case. Subdirectory installs (`/blog/wp-login.php`) still match; look-alike files (`/foo-wp-login.php`) do not
- **Without Cloudflare, IPv6 visitors from blocked countries were never geo-blocked**, because only the IPv4 country lists were downloaded. The IPv6 lists are downloaded too and searched as a sorted index. If one of the two downloads fails, the other is still saved and the previous list for the failed one is kept
- **When every visitor resolved to one proxy or private address, a few failed logins banned the whole site, administrators included.** This happened behind an unconfigured reverse proxy, or behind a configured one whose forwarded header was missing. Private, reserved, loopback, link-local and carrier-grade NAT addresses, and configured trusted proxies, are no longer counted or banned. Blacklist, whitelist, geo and bot checks still apply to them

### Fixed
- With Redis, a crash between the two commands of an increment could leave a counter that never expired. Increments are now a single atomic step, and counters already left without an expiry get one. A dropped Redis connection no longer causes a fatal error during login or page requests; the backend fails open like the others
- The `.htaccess` country block was written even with the firewall's master switch off, so those visitors stayed blocked. It is now written only while the firewall, geo blocking and at least one country are all on. `wp lw-firewall config reset` now updates `.htaccess` like `config set`, and the weekly country-list download is removed when geo blocking is off
- Settings pinned in `wp-config.php` were written into the database by the LW Site Manager block/unblock IP actions and by the bot-list form field, and stayed there after the constant was removed. Only stored values are saved now
- A renamed plugin directory produced an MU-plugin worker that installed but never ran. The installed worker now points at the actual plugin directory and is reinstalled if the directory changes

## [1.5.8] - 2026-09-17

### Changed
- **The default bot list no longer blocks the AI agents that send traffic back.** `ChatGPT-User`, `ClaudeBot`, `PerplexityBot` and `Meta-ExternalFetcher` are out: the first and last fetch a page because a human asked for it, and the other two cite their sources with a link. Blocking them cost referral traffic rather than saving load. Pure training crawlers (`GPTBot`, `Meta-ExternalAgent`, `Bytespider`, `Amazonbot`, `cohere-ai`) and the SEO/scraper crawlers are unchanged
- **Anthropic's retired `claude-web` and `anthropic-ai` entries were removed.** Neither agent has existed since ClaudeBot replaced them, so the rules only ever matched unrelated User-Agents by accident
- **Sites that never edited the bot list get the new default once, on update.** Activation writes the full default set into the database, so a defaults change alone would never reach an existing install. The rewrite only fires when the stored list still matches the one shipped through 1.5.7 — add, remove or change a single entry and your list is left exactly as it is

## [1.5.7] - 2026-09-06

### Fixed
- The release package and the Composer/Packagist dist no longer ship tests, docs or development configuration (`.gitattributes` export-ignore plus unified release excludes). A hosting malware scanner had flagged a unit-test fixture on a customer site

## [1.5.6] - 2026-08-28

The rest of the external security audit of 1.5.4. Every item was reproduced
against the source before being changed.

### Security
- **Reverse proxy support.** Behind the common "nginx in front of Apache on the same host" layout every request arrived as `127.0.0.1`, which the worker treated as the server's own address and exempted from every check — a silent, total bypass while the Status tab reported health. Trusted proxies can now be listed under IP Rules → Reverse Proxy; the forwarded chain is read right to left, skipping trusted hops. It stays opt-in because a forwarded header is client-controlled until the hop that set it is known
- **The Status tab now says when the firewall cannot see real visitor addresses**, instead of looking healthy while every visitor shares one bucket
- **The server's own hostname is no longer resolved into a firewall exemption.** `SERVER_NAME` comes from the client's `Host` header under Apache's default `UseCanonicalName Off`, so this handed an attacker a full bypass for any address they could point a hostname at — cached for five minutes on top
- **Endpoints are classified on the decoded path, not the raw URI.** A substring search let the query string impersonate a path: `/wp-json/x?next=/wp-cron.php&doing_wp_cron=1` skipped rate limiting entirely, and an innocent `?redirect=/wp-login.php` was billed to the login quota. The cron loopback marker is only honoured on the cron path itself, and `?rest_route=` is recognised as REST
- **The country header must come from Cloudflare.** Any non-empty `CF-IPCountry` was believed and short-circuited the CIDR fallback, so a visitor from a blocked country could send `CF-IPCountry: US` straight to the origin. It now clears the same trust test as the client IP and must be exactly two letters
- **A refused password reset no longer drains the hourly email quota.** The site-wide counter was charged before the per-account check, so a flood against one account could exhaust it and deny resets to everyone else. Proof-of-render failures count against the sender only
- **Proof-of-render tokens carry a per-render nonce and a signed scope.** Signing only the timestamp meant every form rendered in the same second produced an identical token — single-use rejected all but the first visitor, and a shared page cache handed one token to everybody. A token issued by one form can no longer be presented to another
- **The file cache is read under a shared lock and never deleted on a parse failure.** A reader racing a writer saw a truncated file and deleted the live key — a ban or a flood counter — under exactly the concurrency the firewall exists to handle. Stored data also refuses object instantiation outright
- **The reset block covers every privileged account**, not just the `administrator` role slug: multisite super admins and custom roles holding `manage_options` are included

### Fixed
- Bans can no longer be permanent by accident: a zero duration meant "no TTL" to every backend. Durations are clamped, and one server-side value policy (`OptionSchema`) now clamps every numeric setting and allowlists every enum — the admin form previously relied on HTML `min`/`max`, which only a browser enforces
- Geo lookups use a pre-packed, sorted range index with a binary search. The default configuration ships six countries, roughly 29,000 CIDRs, and every request without a Cloudflare header walked all of them. Measured at ~0.0003 ms per lookup against ~31 ms before. An older cache file is still read the old way, so an upgrade works before the weekly refresh runs
- The CIDR cache is written to a temporary file and renamed, so a request reading it mid-update can no longer see a half-written include and fail open
- The file backend counts in a fixed window like Redis and APCu. Re-stamping the expiry on every increment made it a sliding window, so the same counter banned on one backend and never banned on another
- APCu uses `apcu_add()` for the first hit; `apcu_store()` let concurrent first requests overwrite each other and undercount exactly at the start of a burst
- APCu and Redis keys are namespaced per installation. A fixed prefix meant two sites sharing one pool collided on counters, bans and single-use tokens
- Expired cache files are swept probabilistically with a batch cap. They were only removed when the identical key was read again, so distributed traffic left dead files forever
- The cache directory's guard files are written unconditionally and cover the geo sub-directory. They used to be created only when the storage backend happened to create the directory first, and the key names are predictable enough to reveal who is banned
- Logging collapses repeated IP/reason pairs for five minutes. Every blocked request used to rewrite the whole log option, turning the defence into a database write amplifier under flood
- An alert that fails to send is retried on the next scan instead of being lost. The baseline snapshot is a deduplication record, not a delivery receipt — one SMTP hiccup permanently lost the notice that an administrator had appeared
- The worker records a heartbeat, and the Status tab reports a worker that is installed but has never run. The version constant is defined before the worker proves it can load anything, so a renamed plugin directory left it looking current while doing nothing
- Storage is resolved once per request. Every call re-ran the availability probes and opened a fresh connection
- The worker self-heals on a content change, not only on a version change. A worker edited without a version bump left the stale copy running against new plugin classes — which can fatal the whole site on a duplicate declaration
- `wp lw-firewall config set` and `config-items` resync `.htaccess`, so a CLI change to the country list reaches the Apache layer
- The registration filter callback no longer hard-types its input; another plugin returning a non-`WP_Error` caused an uncatchable TypeError on a public form
- The LW Plugins page no longer fatals on a remote registry record missing a key, and admin notices are only hidden on this plugin's own screens rather than any screen whose ID contains `lw-`
- The worker's log entry sanitizes the User-Agent like every other producer
- Deactivation clears the geo cron; uninstall removes the cache tree recursively and drops every schedule
- `Requires at least` corrected to 6.2 — the administrator password-change detection uses a hook added in 6.2 and silently never fired below it

### Removed
- `X-XSS-Protection`, which is deprecated and counterproductive in modern browsers

## [1.5.5] - 2026-08-28

Fixes from an external security audit of 1.5.4. Every item below was reproduced
against the source before being changed.

### Security
- A malformed CIDR prefix no longer matches every address. `10.0.0.0/foo` and `10.0.0.0/-1` were cast straight to int, producing a zero-width mask — one typo in the whitelist silently disabled the firewall, one in the blacklist took the site down. The prefix must now be an exact decimal within the family's range, and a malformed rule simply does not match
- A ban is now enforced whenever the firewall is on. The worker only read the ban key when auto-ban or the login lockout happened to be enabled, so bans written by registration spam, password-reset floods or a manual CLI/admin action were listed as active while the address browsed the site freely
- `safe_redirect_path()` folds backslashes to slashes. Browsers treat a leading backslash like a slash, so `/\evil.example/` survived the previous ltrim and reached the `Location` header as a protocol-relative, cross-origin redirect

### Fixed
- wp-config.php constants now apply to the runtime. `Options::get()` honoured them but `Options::get_all()` did not, and the worker, the hook bootstrap, the .htaccess sync and the status screen all read `get_all()` — including the master `enabled` switch. Saving reads the stored values through the new `Options::get_stored()`, so a pinned value is never written into the database
- The settings screen now names the options a constant has pinned, instead of letting an operator edit a field that has no effect
- Unblocking an address also clears the worker's per-endpoint rate counters. Clearing only the threshold counters left an unbanned address refused until the rate window aged out, while the admin screen reported it released

### Removed
- The `geo_action` setting. It has never been read at runtime — the worker always returned 403 and the .htaccess rule was always `[F,L]`. It is unimplementable as documented: geo blocking applies to every path, so redirecting a blocked visitor to the homepage would loop forever. The UI field, the option and the documentation are gone rather than pretending to offer a choice

## [1.5.4] - 2026-08-27

### Added
- The Automatic Bans table now has a search box, reason filters and pagination. 1.5.3 rendered every row on one page — the ban index holds up to 500 entries, so a single botnet run made the screen unusable exactly when it mattered most
- Search matches partial addresses, because the support flow is "the customer gave me their IP"
- Reason filter chips carry counts taken from the whole list, not the visible page, so "login attack or reset flood?" is answered before reading a row
- Summary strip above the table: how many bans are enforced now, how many are tracked but no longer enforced, how many expire within the hour, and which backend holds them
- Checkbox selection with an Unblock selected bulk action; the old Unblock all button remains, moved out of the way and styled as the destructive action it is
- Each row shows both a relative and an absolute time for the ban and its expiry

### Changed
- Search, filtering and paging all run on the rendered rows rather than reloading the page. The table sits inside the settings form, so a `?paged=2` link would navigate away and silently discard unsaved settings on the other tabs

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
