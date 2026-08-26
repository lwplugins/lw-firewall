# LW Firewall — CLI Reference

## Status

```bash
wp lw-firewall status
```

Shows firewall status overview: enabled, storage, rate limit, worker status, etc.

## Configuration

```bash
# List all settings
wp lw-firewall config list
wp lw-firewall config list --format=json

# Set a value
wp lw-firewall config set rate_limit 50
wp lw-firewall config set enabled true
wp lw-firewall config set storage apcu
wp lw-firewall config set action 429

# Reset to defaults
wp lw-firewall config reset --yes
```

## Blocked Bots

```bash
# List blocked User-Agents
wp lw-firewall bots list
wp lw-firewall bots list --format=json

# Add a bot
wp lw-firewall bots add "newbot/1.0"

# Remove a bot
wp lw-firewall bots remove "newbot/1.0"
```

## Logs

```bash
# View recent logs
wp lw-firewall logs list
wp lw-firewall logs list --limit=50
wp lw-firewall logs list --format=json

# Clear all logs
wp lw-firewall logs clear --yes
```

## Worker Management

```bash
# Install/reinstall the MU-plugin worker
wp lw-firewall worker install

# Remove the worker
wp lw-firewall worker remove
```

## IP Management

```bash
# List whitelist or blacklist
wp lw-firewall ip list whitelist
wp lw-firewall ip list blacklist
wp lw-firewall ip list whitelist --format=json

# Add an IP or CIDR range
wp lw-firewall ip add whitelist 192.168.1.100
wp lw-firewall ip add blacklist 10.0.0.0/8

# Remove an IP or CIDR range
wp lw-firewall ip remove whitelist 192.168.1.100
wp lw-firewall ip remove blacklist 10.0.0.0/8
```

## Geo Blocking

```bash
# List blocked countries
wp lw-firewall geo list
wp lw-firewall geo list --format=json

# Add a country (ISO 3166-1 alpha-2 code)
wp lw-firewall geo add CN
wp lw-firewall geo add RU

# Remove a country
wp lw-firewall geo remove CN

# Update CIDR cache for all blocked countries
wp lw-firewall geo update
```

## New Administrator Alerts

```bash
# Show alert configuration and monitoring state
wp lw-firewall alerts status

# Run the reconciliation scan now (also usable from a system cron
# when WP-Cron is disabled)
wp lw-firewall alerts scan

# Send a test alert to the configured recipients
wp lw-firewall alerts test

# Inspect the known-administrator snapshot
wp lw-firewall alerts baseline

# Re-take the snapshot from the current administrator list
# (everything present now is treated as known and will not alert)
wp lw-firewall alerts baseline --reset
```

Relevant settings: `admin_alert_enabled`, `admin_alert_email`,
`admin_alert_scan_enabled`, `admin_alert_changes` — settable with
`wp lw-firewall config set`.

```bash
wp lw-firewall config set admin_alert_enabled true
wp lw-firewall config set admin_alert_email security@example.com

# Turn off takeover tracking (username / email / password changes on
# administrators that already existed)
wp lw-firewall config set admin_alert_changes false
```

The snapshot stores, per administrator: user ID, username, email address and a
SHA-256 digest of the stored password hash. The digest only answers "did this
change?" — no password or usable hash is kept.

## Password Reset Flood Protection

Covers `wp-login.php?action=lostpassword` **and** the WooCommerce
"Lost your password?" form — both pass through the same `lostpassword_post`
hook. Requests started by a user with `edit_users`, or by WP-CLI, are never
limited, so the Users screen "Send password reset link" action and any
provisioning script keep working during a flood.

```bash
# Show every reset setting and the option key behind it
wp lw-firewall reset status
wp lw-firewall reset status --format=json

# Turn protection on / off (limits are kept when off, so turning it
# back on restores the same configuration)
wp lw-firewall reset on
wp lw-firewall reset off

# Turn it on with the optional hardening in one go
wp lw-firewall reset on --proof --auto-ban --alert

# Also take administrator accounts out of the reset flow entirely.
# A locked-out admin then needs WP-CLI or another administrator.
wp lw-firewall reset on --block-admins
```

### The three limits

A reset flood has three shapes and each needs its own counter:

| Option | Default | What it stops |
|--------|---------|---------------|
| `reset_ip_max` / `reset_ip_window` | 5 / 900s | One host hammering the form |
| `reset_user_max` / `reset_user_window` | 3 / 3600s | Many hosts flooding **one account's inbox** — per-IP limiting cannot see this |
| `reset_global_max` | 30 / hour | Total reset emails per hour; protects the mail quota and your domain's sending reputation |

Set any `*_max` to `0` to disable that axis. The per-account counter is keyed
by user ID, so `admin`, `Admin` and the account's email address share one
bucket. Once an IP is over its own limit the request is refused without
touching the target counter, so an attacker cannot use their own flood to lock
the victim out of a genuine reset.

Only the per-IP and failed-token verdicts can trigger `reset_auto_ban`: an
account or site-wide limit says nothing about who happened to ask last.

### All reset options

Every key is also settable with `wp lw-firewall config set`, and overridable
from `wp-config.php` as `LW_FIREWALL_<KEY IN UPPERCASE>`:

```bash
wp lw-firewall config set reset_protect_enabled true
wp lw-firewall config set reset_user_max 3
wp lw-firewall config set reset_proof_enabled true    # token + honeypot on wp-login
wp lw-firewall config set reset_min_fill_time 2       # seconds the form must be open
wp lw-firewall config set reset_token_max_age 3600    # how long a rendered form stays valid
wp lw-firewall config set reset_single_use true       # one request per rendered form
wp lw-firewall config set reset_auto_ban true
wp lw-firewall config set reset_ban_duration 3600
wp lw-firewall config set reset_alert_enabled true    # uses the Alerts tab recipients
wp lw-firewall config set reset_block_admins false
```

`reset_proof_enabled` is enforced only on wp-login.php, because WooCommerce and
custom login pages render their own form and never include the token. Turn it
off if a login plugin replaces the wp-login form. The rate limits apply to
every form regardless.

The timing settings are deliberately separate from the registration ones
(`register_min_fill_time`, `register_token_max_age`, `register_single_use`),
which govern only the registration form. The defaults are identical, so
behaviour is unchanged until you tune one of them.

Note: the proof-of-render token is derived from the issue timestamp, so two
forms rendered in the same second carry the same token. Single-use entries are
namespaced per form (`reg` / `reset`) so registration and lost-password cannot
consume each other's — but two visitors loading the *same* form in the same
second will see the second submission rejected as a replay. On a lost-password
form that is rare enough to be the right trade.

## Configuration via wp-config.php

Settings can be overridden via constants in `wp-config.php`:

```php
define( 'LW_FIREWALL_ENABLED', true );
define( 'LW_FIREWALL_STORAGE', 'apcu' );
define( 'LW_FIREWALL_RATE_LIMIT', 50 );
define( 'LW_FIREWALL_RATE_WINDOW', 120 );
define( 'LW_FIREWALL_ACTION', '429' );
define( 'LW_FIREWALL_LOG_ENABLED', true );
```
