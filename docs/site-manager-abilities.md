# LW Firewall - Site Manager Abilities

LW Firewall registers abilities with [LW Site Manager](https://github.com/lwplugins/lw-site-manager) when both plugins are active. These abilities expose firewall management to the REST API and AI agents.

## Category

`firewall` - Firewall management abilities: rate limiting, IP blocking, bot control and logs.

## Abilities

### `lw-firewall/get-options` (read-only)

Returns all LW Firewall settings merged with defaults.

**Input:** none

**Output:**
```json
{
  "success": true,
  "options": {
    "enabled": true,
    "rate_limit": 30,
    "rate_window": 60,
    "ip_blacklist": [],
    "ip_whitelist": [],
    "blocked_bots": ["gptbot", "claudebot"],
    "geo_enabled": true,
    "blocked_countries": ["CN", "RU"],
    "..."
  }
}
```

**Permission:** `can_manage_options`

---

### `lw-firewall/get-log` (read-only)

Returns recent blocked request log entries. Requires `log_enabled` to be active in settings.

**Input:**
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | integer | 25 | Number of entries to return (1-100) |

**Output:**
```json
{
  "success": true,
  "entries": [
    { "ip": "1.2.3.4", "reason": "rate_limit", "ua": "...", "url": "/wp-login.php", "time": "2025-01-01 12:00:00" }
  ],
  "total": 42
}
```

**Permission:** `can_manage_options`

---

### `lw-firewall/list-blocked` (read-only)

Returns all IP addresses and CIDR ranges currently on the manual blacklist.

**Input:** none

**Output:**
```json
{
  "success": true,
  "ips": ["1.2.3.4", "10.0.0.0/8"],
  "total": 2
}
```

**Permission:** `can_manage_options`

---

### `lw-firewall/block-ip` (write)

Adds an IP address or CIDR range to the blacklist.

**Input:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string | yes | IP address (e.g. `1.2.3.4`) or CIDR range (e.g. `10.0.0.0/8`) |

**Output:**
```json
{ "success": true, "message": "1.2.3.4 has been added to the blacklist." }
```

**Errors:** `400 missing_ip`, `400 invalid_ip`

**Permission:** `can_manage_options`

---

### `lw-firewall/unblock-ip` (write)

Removes an IP address or CIDR range from the blacklist.

**Input:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string | yes | IP address or CIDR range to remove |

**Output:**
```json
{ "success": true, "message": "1.2.3.4 has been removed from the blacklist." }
```

**Errors:** `400 missing_ip`, `404 ip_not_found`

**Permission:** `can_manage_options`

---

## Notes

- All abilities require the `manage_options` capability.
- The blacklist changes (`block-ip` / `unblock-ip`) are persisted immediately via `Options::save()`.
- Auto-banned IPs (set by `AutoBanner` in storage) are separate from the manual blacklist and cannot be managed through these abilities.
- Log entries are only available when `log_enabled` is `true` in the firewall settings.
