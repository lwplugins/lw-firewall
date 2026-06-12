# Registration Spam Protection — Design

**Date:** 2026-06-12
**Plugin:** lw-firewall
**Target version:** 1.4.0

## Problem

Spam bots create fake accounts via `wp-login.php?action=register` when
`users_can_register` is enabled. Two distinct bot classes attack this endpoint:

1. **Generic form-fillers** — render the page and fill every `<input>`,
   including hidden ones.
2. **WordPress-aware direct-POST bots** — know the default register form has
   exactly `user_login` + `user_email`, so they craft a POST directly without
   ever rendering the HTML.

A classic "reject-if-hidden-field-is-filled" honeypot only catches class 1.
Class 2 never sees the honeypot field, so it sails through. Class 2 is the
dominant serious threat on this endpoint.

## Approach

Invert the honeypot: instead of trapping a field that gets *filled*, require a
field that can only exist if the form was *actually rendered* — a server-issued
signed token. A direct-POST bot that never fetched the form cannot produce a
valid token.

Layered defense (strongest first):

| Layer | Catches | Bot class |
|-------|---------|-----------|
| Signed render-token (HMAC + timing + single-use) | direct-POST bots | class 2 |
| Honeypot (secondary, cheap) | generic form-fillers | class 1 |
| RegisterTracker → auto-ban | persistent render-loop bots | the remainder |

A sophisticated bot can GET the form, scrape the token, then POST it — but that
forces a render → parse → wait → submit loop, one token per attempt, which is
exactly where timing + single-use + the existing auto-ban bite.

No external services, no captcha, no tracking — consistent with the plugin's
lightweight philosophy.

## Architecture

```
Spam tab (admin)                  Frontend flow (wp-login.php?action=register)
─────────────────                 ─────────────────────────────────────────────
TabSpam.php  ──► options          register_form   ──► RegisterGuard::render_fields()
                                  │                    (signed token + honeypot injected)
                                  │
                                  registration_errors ──► RegisterGuard::validate()
                                       │                  token missing/invalid/expired
                                       │                  OR honeypot filled
                                       │                  OR too fast  → WP_Error (reject)
                                       │                                └► RegisterTracker::record_reject()
                                       │                                      ├─ storage increment register_reject_<ip>
                                       └─ valid ──► WP continues              └─ over threshold → AutoBanner::ban()
```

The registration flow runs inside normal WordPress (wp-login.php bootstraps
WP), **not** the MU-plugin worker. Hooks are wired in
`Plugin::init_runtime_hooks()`, mirroring the existing `login_limit_enabled`
brute-force protection. Repeat-offender banning reuses `AutoBanner`, so the
worker blocks the banned IP before WP loads on subsequent requests.

### Scope boundary

Covers **only** the default WordPress `?action=register` flow — the
`register_form` and `registration_errors` hooks fire only there. WooCommerce
and other custom registration flows are untouched, so they are not broken.

## Components

### New files (all PSR-4, within size limits)

| File | Responsibility | Est. lines |
|------|----------------|-----------|
| `includes/Admin/Settings/TabSpam.php` | Spam tab UI (toggles), uses `FieldRendererTrait` | ~90 |
| `includes/Rules/RegisterGuard.php` | Inject + validate token/honeypot on the register form | ~140 |
| `includes/Rules/RegisterToken.php` | HMAC token issue/verify (stateless + single-use) | ~70 |
| `includes/Rules/RegisterTracker.php` | Count rejections per IP → `AutoBanner` (mirror of `LoginTracker`) | ~90 |
| `tests/register-token-test.php` | Dependency-free test for `RegisterToken` | — |

### Modified files

| File | Change |
|------|--------|
| `includes/Options.php` | 7 new defaults (see Settings) |
| `includes/Admin/SettingsPage.php` | Add `TabSpam` to `$tabs` (after `TabProtection`) |
| `includes/Plugin.php` | Wire register hooks behind `register_protect_enabled` + `users_can_register` guard |

## Token mechanism (`RegisterToken`)

Hidden field injected into the rendered form:

```
token = base64( issued_at ":" hmac )
hmac  = hash_hmac( 'sha256', issued_at, wp_salt('nonce') )
```

`wp_salt('nonce')` is per-site stable and secret — no separate secret to store
or manage. `issued_at` is the UNIX render time.

Validation in `registration_errors`:

1. **Missing / malformed** → reject. *(catches direct-POST bots — never
   rendered, no token)*
2. **HMAC mismatch** → reject. *(unforgeable; salt is secret)*
3. **Too old** (`now - issued_at > register_token_max_age`) → reject.
   *(replay / expiry)*
4. **Too fast** (`now - issued_at < register_min_fill_time`) → reject.
   *(timing — a rendering bot that submits instantly is caught)*
5. **Single-use** (when `register_single_use`): the used token's hash is written
   to the existing storage backend (apcu/redis/file) with TTL = `max_age`. A
   second sighting → reject. Kills token farming. Reuses the storage layer the
   plugin already has.

Layers 1–4 are stateless (zero storage). Layer 5 adds one storage write+read
per registration and is enabled by default.

## Settings (Spam tab)

New keys in `Options::get_defaults()`, `register_` prefix, mirroring the login
protection pattern:

| Option | Default | Controls |
|--------|---------|----------|
| `register_protect_enabled` | `false` | Master toggle (only active when `users_can_register`) |
| `register_min_fill_time` | `2` | Timing threshold (seconds) — faster POST = bot |
| `register_token_max_age` | `3600` | Token lifetime (seconds) |
| `register_honeypot` | `true` | Secondary honeypot field |
| `register_single_use` | `true` | Single-use token (storage-backed) |
| `register_ban_threshold` | `3` | Rejections before ban (per IP) |
| `register_ban_duration` | `3600` | Ban length (seconds) |

`TabSpam` uses `FieldRendererTrait` like the other tabs. Saving goes through the
existing `SettingsSaver` (which iterates `get_defaults()` keys) — no change
needed there.

## Wiring (`Plugin.php`)

```php
if ( ! empty( $options['register_protect_enabled'] ) && get_option( 'users_can_register' ) ) {
    add_action( 'register_form', [ RegisterGuard::class, 'render_fields' ] );
    add_filter( 'registration_errors', [ RegisterGuard::class, 'validate' ], 10, 3 );
}
```

The `users_can_register` guard skips the hooks entirely when registration is
closed — no point protecting a disabled endpoint.

## Error handling

- A failed token/honeypot/timing check returns a generic `WP_Error` ("Registration
  failed, please try again.") — no detail that would help a bot tune its attack.
- `RegisterGuard::validate()` must never fatal: missing `$_POST` keys, invalid
  base64, or a dead storage backend degrade to "reject this registration" (for a
  validation failure) or "skip single-use only" (if storage is unavailable),
  never to a PHP error on the login page.
- `RegisterTracker` skips whitelisted IPs (reuse `IpMatcher` + `ip_whitelist`),
  exactly like `LoginTracker`.

## Testing

No PHPUnit infra exists; use a dependency-free script in TDD order (test first).

`php tests/register-token-test.php` covers `RegisterToken` issue/verify:

- valid + fresh token → pass
- missing token → reject *(direct-POST bot)*
- tampered HMAC → reject *(forgery)*
- expired (`max_age` + 1) → reject
- too fast (< `min_fill_time`) → reject
- single-use: same token twice → reject (with a mock storage)

`RegisterGuard` / `RegisterTracker` are hook-bound; verify via `composer phpcs`
and manual checks. Confirm exact hook signatures (`register_form`,
`registration_errors` 3-arg) against WP source at implementation time.

## Versioning

Bump 1.3.0 → 1.4.0 across all release locations: `lw-firewall.php` (×2),
`worker/lw-firewall-worker.php` (×2 — version guard, even though the worker has
no logic change), `readme.txt`, `CHANGELOG.md`. CI fails if plugin and worker
versions diverge.

## Out of scope / follow-ups

- **Disposable-email domain blocklist** — optional opt-in toggle
  (`register_block_disposable`, default off) rejecting throwaway-domain emails
  via a bundled static list. Deferred: introduces a maintained data file; ships
  better as a separate opt-in extra. (GH issue to be filed.)
- **Trusted-proxy / forwarded-IP support in `IpDetector`** — separate parked
  feature, fully brainstormed; status-tab diagnostic captured in GH issue #6.
- **Captcha / Turnstile / hCaptcha** — rejected: external script + friction +
  (mostly) tracking, against the plugin's philosophy.
