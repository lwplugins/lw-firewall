# LW Firewall

WooCommerce filter rate limiter — blocks bots crawling filter combinations and rate-limits requests per IP.

[![PHP Version](https://img.shields.io/badge/PHP-8.1%2B-blue.svg)](https://php.net)
[![WordPress Version](https://img.shields.io/badge/WordPress-6.0%2B-blue.svg)](https://wordpress.org)
[![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

## The Problem

Bots systematically crawl every WooCommerce filter combination (`?pa_color=red&pa_size=xl&min_price=10&...`), generating thousands of uncacheable requests that overload your server.

## How It Works

LW Firewall installs an MU-plugin worker that intercepts requests **before WordPress fully loads**, blocking malicious bots and rate-limiting IPs with minimal overhead.

## Features

### Bot Blocking

- Block requests by User-Agent substring matching (case-insensitive)
- 20+ known bad bots blocked by default (AhrefsBot, SemrushBot, DotBot, etc.)
- Add/remove bot patterns via admin UI or WP-CLI

### Rate Limiting

- Per-IP request counter for WooCommerce filter URLs
- Configurable threshold (default: 30 requests) and time window (default: 60 seconds)
- Configurable action: **429 Too Many Requests** or **302 redirect to homepage**
- Only triggers on URLs with filter query parameters

### Storage Backends

| Backend | Speed | Persistence | Requirement |
|---------|-------|-------------|-------------|
| **APCu** | Fastest | Per-process | `apcu` extension |
| **Redis** | Fast | Shared | `redis` extension + server |
| **File** | Fallback | Disk-based | Always available |

Auto-detection picks the best available backend.

### MU-Plugin Worker

- Loads on `muplugins_loaded` (priority 1) — before themes and plugins
- Own autoloader — zero dependency on WordPress plugin system
- Automatic install on activation, removal on deactivation

### Cloudflare Support

- Automatic real IP detection via `CF-Connecting-IP` header
- Cloudflare IP range validation to prevent header spoofing

### Request Logging

- Optional logging of blocked requests (time, IP, reason, User-Agent, URL)
- Admin log viewer with table display
- One-click log clearing

## Installation

**Via Composer:**

```bash
composer require lwplugins/lw-firewall
```

**Manual:**

1. Download the latest release ZIP
2. Upload to `/wp-content/plugins/`
3. Activate in WordPress admin

## Settings

Navigate to **LW Plugins > Firewall** in the admin panel.

| Tab | Description |
|-----|-------------|
| **General** | Enable/disable, storage backend, rate limit, time window, action, filter params |
| **Bots** | Manage blocked bot User-Agent patterns |
| **Status** | MU-plugin worker status, active storage backend, reinstall worker |
| **Logs** | Enable logging, view blocked requests, clear log |

## WP-CLI Commands

```bash
# Show firewall status overview
wp lw-firewall status

# Configuration
wp lw-firewall config list
wp lw-firewall config set rate_limit 50
wp lw-firewall config set storage redis
wp lw-firewall config reset --yes

# Bot management
wp lw-firewall bots list
wp lw-firewall bots add "BadBot/1.0"
wp lw-firewall bots remove "BadBot/1.0"

# Log management
wp lw-firewall logs list --limit=50
wp lw-firewall logs clear --yes

# MU-plugin worker
wp lw-firewall worker install
wp lw-firewall worker remove
```

## wp-config.php Overrides

Override any setting via constants (takes precedence over admin UI):

```php
define( 'LW_FIREWALL_ENABLED', true );
define( 'LW_FIREWALL_STORAGE', 'apcu' );       // apcu, redis, file
define( 'LW_FIREWALL_RATE_LIMIT', 30 );
define( 'LW_FIREWALL_RATE_WINDOW', 60 );        // seconds
define( 'LW_FIREWALL_ACTION', '429' );           // 429 or redirect
define( 'LW_FIREWALL_LOG_ENABLED', false );
```

## Requirements

- PHP 8.1 or higher
- WordPress 6.0 or higher
- WooCommerce (recommended, but not required)

## Part of LW Plugins

LW Firewall is part of the [LW Plugins](https://github.com/lwplugins) family — lightweight WordPress plugins with minimal footprint and maximum impact.

| Plugin | Description |
|--------|-------------|
| [LW SEO](https://github.com/lwplugins/lw-seo) | Essential SEO features without the bloat |
| [LW Disable](https://github.com/lwplugins/lw-disable) | Disable WordPress features like comments |
| [LW Site Manager](https://github.com/lwplugins/lw-site-manager) | Site maintenance via AI/REST |
| [LW Memberships](https://github.com/lwplugins/lw-memberships) | Lightweight membership system |
| [LW ZenAdmin](https://github.com/lwplugins/lw-zenadmin) | Clean up your admin — notices sidebar & widget manager |
| [LW Cookie](https://github.com/lwplugins/lw-cookie) | GDPR-compliant cookie consent |
| **LW Firewall** | WooCommerce filter rate limiter & bot blocker |

## License

GPL-2.0-or-later. See [LICENSE](https://www.gnu.org/licenses/gpl-2.0.html) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
