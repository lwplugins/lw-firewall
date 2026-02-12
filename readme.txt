=== LW Firewall ===
Contributors: developer
Tags: woocommerce, firewall, rate-limit, bot-blocker, security
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 8.1
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WooCommerce filter rate limiter — blocks bots crawling filter combinations and rate-limits requests per IP.

== Description ==

LW Firewall protects WooCommerce shops from bots that endlessly crawl filter/facet combinations, causing PHP-FPM overload and database bloat.

**Features:**

* Bot blocking by User-Agent (customizable list)
* IP-based rate limiting for filter/facet requests
* Cloudflare-aware IP detection (CF-Connecting-IP)
* Multiple storage backends: APCu, Redis, file-based fallback
* MU-plugin worker for early request interception
* Tabbed admin settings page under LW Plugins menu
* Optional request logging with viewer
* Full WP-CLI support

**How it works:**

1. An MU-plugin worker intercepts requests before any theme or plugin code runs
2. If the request contains WooCommerce filter parameters (e.g., `filter_color`, `query_type_size`)
3. Known bots are immediately blocked with 403
4. Other visitors are rate-limited — exceeding the limit triggers a 302 redirect or 429 response

== Installation ==

1. Upload the `lw-firewall` folder to `/wp-content/plugins/`
2. Activate the plugin — the MU-plugin worker is installed automatically
3. Configure settings under LW Plugins > Firewall

Or install via Composer:

    composer require lwplugins/lw-firewall

== Changelog ==

= 1.0.0 =
* Initial release
