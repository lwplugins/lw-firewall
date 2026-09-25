=== LW Firewall ===
Contributors: developer
Tags: firewall, rate-limit, bot-blocker, security, woocommerce
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 1.6.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight WordPress firewall — rate-limits endpoints, blocks bots, bans repeat offenders, and adds security headers.

== Description ==

LW Firewall installs an MU-plugin worker that intercepts requests **before WordPress fully loads**, protecting your server from bots, brute-force attacks, DDoS, and vulnerability scanners.

**Processing order:**

1. IP Whitelist — whitelisted IPs skip all checks
2. IP Blacklist — blacklisted IPs get 403 immediately
3. Geo Blocking — block entire countries (Cloudflare header or CIDR lookup)
4. Auto-Ban — previously banned IPs get 403
5. 404 Flood — IPs with excessive 404s get 429
6. Bot Blocking — User-Agent matching (all requests)
7. Endpoint Detection — filter params, cron, xmlrpc, login, REST API
8. Rate Limiting — per-IP counters with auto-ban escalation

**Endpoint Protection:**

* WooCommerce filters — rate limit + bot blocking
* `wp-login.php` — brute-force rate limiting
* `wp-cron.php` — DDoS rate limiting
* `xmlrpc.php` — DDoS/brute-force rate limiting
* REST API (`/wp-json/`) — rate limiting
* 404 flood — vulnerability scanner blocking

**Features:**

* Geo Blocking — block visitors by country (Cloudflare or CIDR fallback), enabled by default for CN, RU, IN, VN, ID, BD
* Apache-level geo blocking via .htaccess — blocks before PHP loads
* Bot blocking by User-Agent (20+ bad bots blocked by default)
* IP whitelist and blacklist with CIDR range support
* Auto-ban — escalating protection for repeat offenders
* Security HTTP headers (X-Content-Type-Options, X-Frame-Options, etc.)
* Cloudflare-aware IP detection (CF-Connecting-IP)
* Multiple storage backends: APCu, Redis, file-based fallback
* MU-plugin worker for early request interception
* Import/Export — transfer firewall settings between sites via JSON
* Password reset flood protection — per-IP, per-account and site-wide limits covering wp-login.php and WooCommerce
* New administrator alert — email notification when any account gains admin rights or an existing admin is modified, including changes written straight into the database
* Tabbed admin settings page under LW Plugins menu (11 tabs)
* Optional request logging with viewer
* Full WP-CLI support
* wp-config.php constant overrides

== Screenshots ==

1. General Settings — configure firewall, storage backend, rate limits and filter parameters

== Installation ==

1. Upload the `lw-firewall` folder to `/wp-content/plugins/`
2. Activate the plugin — the MU-plugin worker is installed automatically
3. Configure settings under LW Plugins > Firewall

Or install via Composer:

    composer require lwplugins/lw-firewall

== Frequently Asked Questions ==

= Does it work without WooCommerce? =

Yes. WooCommerce filter protection is optional. The firewall also protects wp-login.php, wp-cron.php, xmlrpc.php, REST API, and 404 floods independently.

= What storage backend should I use? =

APCu is fastest (in-memory, per-process). Redis is fast and shared across processes. File-based is the fallback that always works. Auto-detection picks the best available.

= Will it block legitimate users? =

Rate limits are per-IP (IPv6 clients per /64 network, the block a single connection is normally given). Casual users won't trigger them. Private and trusted-proxy addresses are never counted or banned, so a misconfigured proxy cannot lock out the whole site. Only bots and attackers sending many requests in a short window get blocked. You can whitelist trusted IPs.

= Does it support Cloudflare? =

Yes. It automatically detects the real visitor IP via the CF-Connecting-IP header with Cloudflare IP range validation to prevent spoofing.

= Can someone lock my account on purpose? =
The per-username lockout locks an account after repeated failed logins from any IP, so anyone who knows a username can keep that account locked by retrying every lock period (15 minutes by default). Whitelisted IPs are never counted or refused: whitelist your own address under IP Rules. Lift an active lock from the Bans list or with `wp lw-firewall user-lock clear`. You can shorten the lock (Username Lock Duration) or turn the feature off.

== Changelog ==

= 1.6.0 =
* New: New settings screen built with WordPress components: side navigation for the eleven sections, a top bar with Save/Discard and a Cmd/Ctrl+S shortcut, loading skeletons and a mobile layout. Only changed settings are saved; an invalid value is shown next to its field and nothing is saved.
* New: Every action has its own button and never saves unsaved edits: unblock (per address, selected or all, with per-address results), manual ban, clear log, reinstall worker, update CIDR lists, run the administrator scan, send a test email, import and export.
* New: Per-username login lockout: after 10 failed logins within the detection window, from any IP, the account is locked for 15 minutes, correct password included. Failures count under the account's real login, so email logins and Unicode look-alike spellings add up to the same lock. Whitelisted IPs bypass it. Lift a lock from the Bans list or with wp lw-firewall user-lock remove <username|email> / clear. login_user_limit_enabled defaults to on, so sites that already have brute-force login protection on get username locking after the update.
* New: The Status tab shows how the firewall sees your IP (REMOTE_ADDR, forwarded headers, trusted proxy match, Cloudflare, routable) (#6), tests the storage backend with a write/read/delete round trip, checks the cache directory, shows geo list freshness per country and alert state, and lists warnings with a badge in the navigation.
* New: The ban list shows the storage backend in use, IPv6 /64 and legacy entries and username locks; administrators can ban an address manually.
* New: The log view has reason labels, a reason filter, search and paging.
* New: Admin REST API under lw-firewall/v1/admin/ for users with manage_options.
* New: Violet accent for the admin and the plugin logo; Hungarian translation of the whole new interface.
* Change: XML-RPC rate limiting is on by default for new installs only. Existing sites, including multisite subsites without their own settings, keep their current setting.
* Change: The Security tab lists exactly the headers that are sent, with what each one protects against.
* Change: The classic settings screen and its stylesheet and script were removed.
* Fix: "Update CIDR lists" works and reports each country for IPv4 and IPv6.
* Fix: Country codes must be ISO 3166-1 codes: "Germany" is rejected instead of being saved as GE, and "CN, RU" on one line keeps both.
* Fix: IP whitelist, blacklist and trusted proxy entries are validated, and invalid entries are reported.
* Fix: An empty Filter Parameters list resets to filter_|30, query_type_|30, limits included.
* Fix: Invalid alert email addresses are reported instead of being dropped silently.
* Fix: Settings pinned in wp-config.php are never written to the database by the admin, the import or WP-CLI.
* Fix: Import keeps settings missing from the file, reads "false" as off, validates every value and reports each setting.
* Fix: The number limits in the admin match the server limits, so a value set through WP-CLI can no longer block saving the form.
* Fix: "Unblock every banned address" reports each address, and a ban the storage refuses to lift stays listed.
* Fix: The administrator scan no longer says "clean" when alerts are off, or "email sent" when the mail was queued.
* Fix: A refusal caused by a locked username no longer counts against the visitor's IP, so an owner retrying with the right password cannot get their own IP banned.
* Fix: The admin can no longer ban the address they are currently using.
* Fix: Worker install errors are shown as sentences, not codes, and the plugin's own warnings (Status, Alerts, import results) are visible again.
* Fix: The admin screen no longer depends on the translated parent-menu name to load.
* Fix: WP-CLI config set rejects invalid values, and config reset leaves wp-config.php-pinned settings alone.
* Fix: List settings are capped at 5000 entries, and settings requests at 256 KB.

= 1.5.10 =
* Fix: Notices from themes and other plugins (for example a theme's purchase-code or recommended-plugins notice) could show on the LW Firewall screen. They are now kept off every LW Plugins screen, whatever their markup
* Fix: LW Firewall's own warnings and messages on its settings tabs (the Status tab's IP and worker warnings, the Alerts tab's pending-queue and mail-error warnings, and the import result) were hidden. They show again

= 1.5.9 =
* Fix: IPv6 clients were counted and banned per address, so an attacker rotating addresses inside one /64 was never limited. Counters and bans now cover the whole /64; unblocking any address in it (or the /64 itself) lifts the ban, including bans created by 1.5.8
* Fix: /wp-login.php/x, /xmlrpc.php/x, /wp-cron.php/x and case variants such as /XMLRPC.php escaped the login, XML-RPC and cron limits. They are now matched like the plain path, and a subdirectory install's own WP-Cron loopback is no longer throttled
* Fix: Without Cloudflare, IPv6 visitors from blocked countries were never geo-blocked because only the IPv4 country lists were downloaded. The IPv6 lists are now downloaded too, and a failed download of one list no longer affects the other
* Fix: When every visitor appeared as one proxy or private address, a few failed logins banned the whole site, administrators included. Private, reserved and trusted-proxy addresses are no longer counted or banned
* Fix: With Redis, a counter could be left without an expiry and a dropped Redis connection could cause a fatal error during login or page requests. Counters now always expire and Redis errors fail open
* Fix: The .htaccess country block stayed active with the firewall switched off, and `wp lw-firewall config reset` did not update it. The weekly country-list download is now removed when geo blocking is off
* Fix: Settings pinned in wp-config.php were written into the database by the LW Site Manager block/unblock IP actions and by the bot-list field
* Fix: A renamed plugin directory produced a worker that installed but never ran. The worker now uses the actual directory

= 1.5.8 =
* Change: The default bot list no longer blocks ChatGPT-User, ClaudeBot, PerplexityBot or Meta-ExternalFetcher — these fetch pages for a real visitor or cite your site with a link, so blocking them cost referral traffic
* Change: Anthropic's retired claude-web and anthropic-ai entries were removed; neither agent exists any more
* Change: Sites that never edited the bot list receive the new default once on update. An edited list is left untouched

= 1.5.7 =
* Fix: the release package and Composer dist no longer ship tests, docs or development configuration

= 1.5.6 =
* Security: Reverse proxy support — behind a same-host proxy every request arrived as 127.0.0.1 and was exempted from every check, silently
* Security: The Status tab now warns when the firewall cannot see real visitor addresses
* Security: The server hostname is no longer resolved into a firewall exemption (it comes from the client's Host header)
* Security: Endpoints are matched on the decoded path — the query string could previously impersonate one and skip rate limiting
* Security: The Cloudflare country header is only trusted from Cloudflare
* Security: A refused password reset no longer drains the hourly email quota for every other user
* Security: Proof-of-render tokens get a per-render nonce and a signed scope
* Security: The file cache is read under a shared lock and never deletes a live key on a partial read
* Fix: Geo lookups use a sorted range index with binary search instead of walking ~29,000 CIDRs per request
* Fix: One server-side value policy clamps every numeric setting and allowlists every enum
* Fix: Per-installation cache keys, fixed counting windows, expired-file sweeping and atomic cache writes
* Fix: Undelivered alerts are retried; the worker reports a heartbeat; logging no longer amplifies floods
* Remove: The deprecated X-XSS-Protection header

= 1.5.5 =
* Security: A malformed CIDR prefix (e.g. `10.0.0.0/foo`) no longer matches every address — a single typo in the IP whitelist could disable the firewall
* Security: Bans are now enforced whenever the firewall is on, not only when auto-ban or the login lockout is enabled
* Security: The rate-limit redirect can no longer be turned into a cross-origin redirect with a backslash
* Fix: wp-config.php constants now apply to the worker and the runtime hooks, not just to single option reads
* Fix: The settings screen shows which options a constant has pinned
* Fix: Unblocking an address also clears the per-endpoint rate counters
* Remove: The `geo_action` setting, which was never read at runtime and cannot work as documented

= 1.5.4 =
* New: Search, reason filters and pagination on the Automatic Bans table — the ban index holds up to 500 entries and 1.5.3 put them all on one page
* New: Summary strip showing what is enforced now, what is only tracked, and what expires within the hour
* New: Checkbox selection with an Unblock selected bulk action
* Change: Filtering and paging happen without reloading, so unsaved settings on other tabs are never lost

= 1.5.3 =
* New: Automatic Bans table on the IP Rules tab — see who is banned and why, with an Unblock button per row
* New: `wp lw-firewall ban list|check|remove|clear` WP-CLI commands
* Fix: Unblocking an IP now also clears the counters behind the ban, so the address is not re-banned on its next request
* New: Bans record their reason (failed logins, registration spam, password-reset flood, rate limit)

= 1.5.2 =
* New: Complete Hungarian translation — the Alerts tab, the password-reset settings, every alert email and the lost-password form messages (127 new strings)
* Update: Regenerated the translation template from the current source

= 1.5.1 =
* New: Password reset flood protection — rate limits per IP, **per targeted account** (stops a distributed flood of one person's inbox, which per-IP limiting cannot see) and a site-wide hourly cap protecting your mail quota
* New: Covers both wp-login.php and the WooCommerce "Lost your password?" form via the shared WordPress hook
* New: Proof-of-render token and honeypot on the wp-login lost-password form, with minimum fill time and single-use tokens (own settings, independent of the registration form); optional auto-ban for offending IPs
* New: Optional hardening that takes administrator accounts out of the password reset flow entirely
* New: Optional throttled email alert when a reset limit is reached
* New: `wp lw-firewall reset status|on|off` WP-CLI command
* Change: Resets started by an administrator or by WP-CLI are never limited, so "Send password reset link" keeps working

= 1.5.0 =
* New: Email alert when an account gains administrator privileges — covers the admin screens, plugins, the REST API and WP-CLI via WordPress hooks, and direct database inserts via an hourly reconciliation scan
* New: Account takeover alert — the snapshot also tracks each administrator's username, email address and password digest, and reports a change on an existing account (the classic email-rewrite takeover leaves the user ID untouched)
* New: Alerts settings tab — recipient address (comma-separated list supported, falls back to the site admin email), scan toggle, run-scan and test-email buttons, monitoring status
* New: `wp lw-firewall alerts status|scan|test|baseline` WP-CLI commands

= 1.4.1 =
* Update: Tested up to WordPress 7.1.

= 1.4.0 =
* Security: Fixed a local file inclusion in geo blocking — blocked-country values are validated before being used to load cached CIDR lists
* Security: Fixed .htaccess directive injection — blocked-country values are validated before being written to .htaccess
* Security: Settings import now validates values the same way the settings form does, so an untrusted import file can no longer inject unsafe options
* Security: Fixed IPv4/IPv6 range matching so a crafted address can't be trusted as Cloudflare or match the wrong allow/deny rule; IPv6 allowlist entries now match regardless of notation
* Fix: A blank entry in the bot list no longer blocks every request
* Fix: File-based rate-limit counters now increment atomically, so parallel floods can't slip past the limit
* Fix: A Redis outage now fails open instead of causing a fatal error
* Fix: Registration single-use tokens are enforced atomically (no token reuse under concurrent submits)
* Change: Logged-in users now get a higher rate limit on REST/filter endpoints (so admin dashboards load) instead of a full exemption; a forged login cookie can no longer disable rate limiting, and login, xmlrpc and cron stay fully throttled
* Update: Minimum PHP is now 8.2; added PHPStan level 5 and a PHPUnit test suite to CI

= 1.3.2 =
* Change: Registration spam protection is now enabled by default on new installs (still only active when "Anyone can register" is on)

= 1.3.1 =
* New: Registration spam protection — signed proof-of-render token + honeypot on wp-login.php?action=register, blocking bot sign-ups without a captcha
* New: Spam settings tab with token timing, single-use enforcement, and per-IP auto-ban for repeated spam registrations
* New: Complete Hungarian (hu_HU) translation — all admin, settings, Spam tab, worker notice, and Site Manager strings now translated
* Update: Regenerated the translation template (lw-firewall.pot)

= 1.3.0 =
* New: Brute-Force Login Protection (fail2ban style). Counts failed login attempts per IP via wp_login_failed and bans the whole IP at the firewall once a configurable threshold is reached — the worker then blocks every request from it before WordPress loads
* New: Three adjustable settings on the Protection tab — Failed Attempts (ban threshold), Detection Window, and Ban Duration. Whitelisted IPs are never counted

= 1.2.7 =
* Fix: MU-plugin worker is now bumped together with the main plugin. The worker's runtime version guard had silently disabled the firewall on sites where 1.2.6 shipped without a matching worker bump
* Internal: Release workflow now fails the build when the main plugin and worker versions diverge, so this can never happen again

= 1.2.6 =
* Change: Added missing `'default' => []` to top-level input_schema of `lw-firewall/get-log` so it can be invoked without arguments

= 1.2.5 =
* New: WP-CLI now handles list-typed options properly. `wp lw-firewall config set filter_params "filter_|30,add-to-cart|10"` accepts comma- or newline-separated entries; `--format=json` and `--format=yaml` preserve types instead of stringifying everything
* New: `wp lw-firewall config get <key>` for inspecting a single setting (returns the raw type with `--format=json|yaml`)
* New: `wp lw-firewall config-items add|remove <key> <entry>` for incremental edits to filter_params, blocked_bots, ip_whitelist, ip_blacklist, blocked_countries
* Fix: List-typed options accidentally saved as a single newline-separated string (e.g. via `wp option update` without `--format=json`) are now coerced to arrays on read, so the worker, admin UI, and CLI all see a proper list. Previously the worker would only honor the first entry
* Fix: Filter Parameters help text said the default was `filter_, query_type_` — actually `filter_|30, query_type_|30`. The descriptions for Enable Firewall, Rate Limit, Rate Limit Action, IP Whitelist/Blacklist (CIDR support), and Blocked User-Agents (case-insensitive substring) were also tightened

= 1.2.4 =
* Fix: Worker is now bulletproof — wraps all logic in try/catch, checks every required class file before running, and refuses to run if its version drifts from the main plugin (prevents fatals during plugin updates)
* New: If the MU-plugin worker is missing or stale, runtime protection is disabled and a detailed admin notice is shown until the worker is restored
* New: `LW_FIREWALL_DISABLE_WORKER` wp-config constant — emergency kill switch
* New: Worker auto-reinstall on `upgrader_process_complete` — closes the post-update race
* New: Status tab shows mu-plugins writability and last install attempt result
* New: Activator records last install attempt outcome (writable check, copy result) for diagnostics

= 1.2.3 =
* Fix: Worker version synced to match plugin version
* Fix: Admin notice when MU-plugin worker installation fails

= 1.2.2 =
* New: LW Site Manager integration - firewall abilities for AI agents
* New: lw-firewall/get-options - get firewall settings
* New: lw-firewall/get-log - get firewall log entries
* New: lw-firewall/list-blocked - list blocked IPs
* New: lw-firewall/block-ip - block an IP address
* New: lw-firewall/unblock-ip - unblock an IP address

= 1.2.1 =
* Sync .htaccess geo blocking rules on plugin activation
* Enable geo blocking by default with pre-defined blocked countries (CN, RU, IN, VN, ID, BD)

= 1.2.0 =
* Add Import/Export settings tab — export all firewall settings as JSON, import on another site
* JSON validation: only known setting keys are accepted, missing keys filled with defaults

= 1.1.9 =
* Add .htaccess CF-IPCountry rewrite — Apache-level geo blocking before PHP loads
* Auto-sync .htaccess on settings save, WP-CLI add/remove, and plugin deactivation
* Add WP-CLI `geo` command: list, add, remove, update blocked countries
* Geo blocking status shown in `wp lw-firewall status`

= 1.1.8 =
* Add Geo Blocking — block visitors by country code
* Cloudflare CF-IPCountry header support (instant, zero-cost)
* CIDR-based fallback for non-Cloudflare setups (weekly auto-update from ipdeny.com)
* New Geo Blocking tab in admin settings
* Configurable block action (403 Forbidden or redirect to homepage)
* Manual CIDR list update button

= 1.1.7 =
* Fix Redis storage: skip Redis backend when authentication is required (prevents NOAUTH fatal error)

= 1.1.6 =
* Bot blocking now applies to all requests, not just filter URLs
* Blocked bots (Baiduspider-render, meta-externalagent, etc.) no longer bypass protection on regular pages, admin-ajax, or REST API
* Per-filter-param rate limit override (e.g. `filter_|30` limits filter requests to 30/window)
* Custom limit uses the lowest value when multiple filter params match

= 1.1.5 =
* Minor fix

= 1.1.4 =
* Hash-based tab navigation on settings page
* New block-brick-fire icon
* Updated ParentPage with SVG icon support from registry
* Suppressed expected PHPCS warnings for CLI and FileStorage

= 1.1.3 =
* Add automatic server/localhost IP whitelisting (127.0.0.1, ::1, SERVER_ADDR, domain IP)
* Add Cloudflare IPv6 ranges to IP detection
* Full IPv6 support for rate limiting, whitelist, blacklist, and CIDR matching

= 1.1.2 =
* Fix release ZIP folder structure

= 1.1.1 =
* Fix plugin description — general WordPress firewall, not WooCommerce-specific
* Update settings page title to "Lightweight Firewall"
* Update screenshot

= 1.1.0 =
* Add wp-login.php brute-force protection
* Add wp-cron.php DDoS protection
* Add xmlrpc.php DDoS protection
* Add REST API rate limiting
* Add 404 flood detection and blocking
* Add IP whitelist and blacklist with CIDR support
* Add auto-ban with escalating violations
* Add security HTTP headers with detailed explanations
* Add Protection tab for endpoint toggles
* Add IP Rules tab for whitelist/blacklist
* Add Security tab for HTTP headers
* Add wp-config.php constant overrides
* Add WP-CLI ip command (list/add/remove whitelist/blacklist)
* Add worker version tracking with auto-update on mismatch
* Add Hungarian (hu_HU) translation
* Update admin UI with 7 settings tabs
* Update WP-CLI status command with all new settings

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 1.6.0 =
New settings screen and per-username login lockout (on whenever login protection is on). XML-RPC rate limiting is now on by default for new installs only. Whitelist your own IP if you log in from a fixed address.

= 1.5.9 =
Security update: IPv6 attackers could evade rate limits and bans by rotating addresses, and some login/XML-RPC URLs escaped the limits. Update recommended.
