=== LW Firewall ===
Contributors: developer
Tags: firewall, rate-limit, bot-blocker, security, woocommerce
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 8.1
Stable tag: 1.1.9
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

* Geo Blocking — block visitors by country (Cloudflare or CIDR fallback)
* Bot blocking by User-Agent (20+ bad bots blocked by default)
* IP whitelist and blacklist with CIDR range support
* Auto-ban — escalating protection for repeat offenders
* Security HTTP headers (X-Content-Type-Options, X-Frame-Options, etc.)
* Cloudflare-aware IP detection (CF-Connecting-IP)
* Multiple storage backends: APCu, Redis, file-based fallback
* MU-plugin worker for early request interception
* Tabbed admin settings page under LW Plugins menu
* Optional request logging with viewer
* Full WP-CLI support
* wp-config.php constant overrides

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

Rate limits are per-IP. Casual users won't trigger them. Only bots and attackers sending many requests in a short window get blocked. You can whitelist trusted IPs.

= Does it support Cloudflare? =

Yes. It automatically detects the real visitor IP via the CF-Connecting-IP header with Cloudflare IP range validation to prevent spoofing.

== Changelog ==

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
