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
