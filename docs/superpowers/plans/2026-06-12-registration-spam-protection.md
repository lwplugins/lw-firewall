# Registration Spam Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop bot registrations on `wp-login.php?action=register` with a signed render-token (proof-of-render + timing + single-use), a secondary honeypot, and repeat-offender auto-banning — no captcha, no external services.

**Architecture:** The registration flow runs in normal WordPress, so hooks are wired in `Plugin::init_runtime_hooks()` (mirroring the existing `login_limit_enabled` brute-force protection), guarded by a new `register_protect_enabled` option AND `users_can_register`. `RegisterGuard` injects fields on `register_form` and validates on `registration_errors`; failures are counted by `RegisterTracker` (mirror of `LoginTracker`) which bans via the existing `AutoBanner`, so the MU-plugin worker blocks repeat offenders before WP loads.

**Tech Stack:** PHP 8.1+, WordPress hooks, PSR-4 autoloading, `hash_hmac`/`wp_salt('nonce')` for the token, the plugin's existing `StorageInterface` backends (apcu/redis/file).

---

## File Structure

**New files:**
- `includes/Rules/RegisterToken.php` — HMAC token issue/verify (stateless + optional single-use). Pure, testable.
- `includes/Rules/RegisterTracker.php` — count rejections per IP → `AutoBanner` (mirror of `LoginTracker`).
- `includes/Rules/RegisterGuard.php` — inject + validate token/honeypot on the register form.
- `includes/Admin/Settings/SpamFields.php` — field row definitions (mirror of `ProtectionFields`).
- `includes/Admin/Settings/TabSpam.php` — thin Spam tab renderer (mirror of `TabProtection`).
- `tests/register-token-test.php` — dependency-free test runner for `RegisterToken`.

**Modified files:**
- `includes/Options.php` — 7 new defaults.
- `includes/Admin/SettingsSaver.php` — persist the 7 new keys (the saver lists keys explicitly; it does NOT auto-iterate).
- `includes/Admin/SettingsPage.php` — add `TabSpam` to `$tabs` + `use`.
- `includes/Plugin.php` — wire register hooks + `use`.
- `lw-firewall.php`, `worker/lw-firewall-worker.php`, `readme.txt`, `CHANGELOG.md` — version bump 1.3.0 → 1.4.0.

---

## Task 1: Add option defaults

**Files:**
- Modify: `includes/Options.php` (inside `get_defaults()` return array, after the `login_lockout_duration` line)

- [ ] **Step 1: Add the 7 register defaults**

In `includes/Options.php`, find:

```php
			'login_lockout_duration' => 3600,
```

Insert immediately after it:

```php
			'register_protect_enabled' => false,
			'register_min_fill_time'   => 2,
			'register_token_max_age'   => 3600,
			'register_honeypot'        => true,
			'register_single_use'      => true,
			'register_ban_threshold'   => 3,
			'register_ban_duration'    => 3600,
```

- [ ] **Step 2: Verify PHP parses**

Run: `php -l includes/Options.php`
Expected: `No syntax errors detected`

- [ ] **Step 3: Commit**

```bash
git add includes/Options.php
git commit -m "feat(spam): add registration spam protection option defaults"
```

---

## Task 2: RegisterToken (TDD)

**Files:**
- Test: `tests/register-token-test.php`
- Create: `includes/Rules/RegisterToken.php`

- [ ] **Step 1: Write the failing test**

Create `tests/register-token-test.php`:

```php
<?php
/**
 * Dependency-free test for RegisterToken. Run: php tests/register-token-test.php
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

define( 'ABSPATH', __DIR__ . '/' );

if ( ! function_exists( 'wp_salt' ) ) {
	/**
	 * Stub WordPress wp_salt() with a fixed secret for deterministic HMACs.
	 *
	 * @param string $scheme Salt scheme (ignored).
	 * @return string
	 */
	function wp_salt( string $scheme = 'auth' ): string {
		return 'unit-test-fixed-salt-value';
	}
}

require __DIR__ . '/../includes/Storage/StorageInterface.php';
require __DIR__ . '/../includes/Rules/RegisterToken.php';

use LightweightPlugins\Firewall\Rules\RegisterToken;
use LightweightPlugins\Firewall\Storage\StorageInterface;

$failures = 0;

/**
 * Assert a condition and track failures.
 *
 * @param string $label Test label.
 * @param bool   $cond  Condition that must be true.
 * @return void
 */
function check_that( string $label, bool $cond ): void {
	global $failures;
	if ( $cond ) {
		echo "PASS: {$label}\n";
	} else {
		echo "FAIL: {$label}\n";
		++$failures;
	}
}

$storage = new class() implements StorageInterface {
	/** @var array<string, mixed> */
	private array $data = [];
	public function get( string $key ): mixed {
		return $this->data[ $key ] ?? null; }
	public function set( string $key, mixed $value, int $ttl ): bool {
		$this->data[ $key ] = $value;
		return true; }
	public function increment( string $key, int $ttl ): int {
		$this->data[ $key ] = (int) ( $this->data[ $key ] ?? 0 ) + 1;
		return $this->data[ $key ]; }
	public static function is_available(): bool {
		return true; }
};

$now = 1000000;
$min = 2;
$max = 3600;

$valid = RegisterToken::make( $now - 10 );
check_that( 'valid fresh token passes', true === RegisterToken::check( $valid, $now, $min, $max ) );

check_that( 'empty token rejected', false === RegisterToken::check( '', $now, $min, $max ) );

$tampered = base64_encode( ( $now - 10 ) . ':deadbeef' );
check_that( 'tampered hmac rejected', false === RegisterToken::check( $tampered, $now, $min, $max ) );

$expired = RegisterToken::make( $now - ( $max + 1 ) );
check_that( 'expired token rejected', false === RegisterToken::check( $expired, $now, $min, $max ) );

$fast = RegisterToken::make( $now );
check_that( 'too-fast token rejected', false === RegisterToken::check( $fast, $now, $min, $max ) );

$single = RegisterToken::make( $now - 10 );
check_that( 'single-use first pass', true === RegisterToken::check( $single, $now, $min, $max, $storage ) );
check_that( 'single-use replay rejected', false === RegisterToken::check( $single, $now, $min, $max, $storage ) );

echo 0 === $failures ? "\nALL PASSED\n" : "\n{$failures} FAILED\n";
exit( 0 === $failures ? 0 : 1 );
```

- [ ] **Step 2: Run test to verify it fails**

Run: `php tests/register-token-test.php`
Expected: Fatal error — `Class "LightweightPlugins\Firewall\Rules\RegisterToken" not found` (file does not exist yet).

- [ ] **Step 3: Write minimal implementation**

Create `includes/Rules/RegisterToken.php`:

```php
<?php
/**
 * Signed, time-bound registration token (proof-of-render).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Issues and verifies an HMAC token embedded in the registration form. A valid
 * token proves the form was actually rendered to a client, which a direct-POST
 * bot cannot fake. Timing and single-use checks defeat the render-and-replay
 * case.
 */
final class RegisterToken {

	/**
	 * Issue a token stamped with the current time.
	 *
	 * @return string
	 */
	public static function issue(): string {
		return self::make( time() );
	}

	/**
	 * Build a token for a given issue time (seam for deterministic tests).
	 *
	 * @param int $issued UNIX timestamp the token was issued.
	 * @return string
	 */
	public static function make( int $issued ): string {
		$issued_str = (string) $issued;
		$hmac       = hash_hmac( 'sha256', $issued_str, self::secret() );

		return base64_encode( $issued_str . ':' . $hmac );
	}

	/**
	 * Verify a token against the current time.
	 *
	 * @param string                $token    Raw token from the form.
	 * @param int                   $min_fill Minimum age in seconds (timing floor).
	 * @param int                   $max_age  Maximum age in seconds (expiry).
	 * @param StorageInterface|null $storage  When given, enforces single-use.
	 * @return bool
	 */
	public static function verify( string $token, int $min_fill, int $max_age, ?StorageInterface $storage = null ): bool {
		return self::check( $token, time(), $min_fill, $max_age, $storage );
	}

	/**
	 * Verify a token against an explicit "now" (seam for deterministic tests).
	 *
	 * @param string                $token    Raw token from the form.
	 * @param int                   $now      Current UNIX timestamp.
	 * @param int                   $min_fill Minimum age in seconds (timing floor).
	 * @param int                   $max_age  Maximum age in seconds (expiry).
	 * @param StorageInterface|null $storage  When given, enforces single-use.
	 * @return bool
	 */
	public static function check( string $token, int $now, int $min_fill, int $max_age, ?StorageInterface $storage = null ): bool {
		if ( '' === $token ) {
			return false;
		}

		$decoded = base64_decode( $token, true );

		if ( false === $decoded || ! str_contains( $decoded, ':' ) ) {
			return false;
		}

		[ $issued, $hmac ] = explode( ':', $decoded, 2 );

		if ( '' === $issued || ! ctype_digit( $issued ) ) {
			return false;
		}

		$expected = hash_hmac( 'sha256', $issued, self::secret() );

		if ( ! hash_equals( $expected, $hmac ) ) {
			return false;
		}

		$age = $now - (int) $issued;

		if ( $age < $min_fill || $age > $max_age ) {
			return false;
		}

		if ( null !== $storage ) {
			$key = 'reg_tok_' . hash( 'sha256', $decoded );

			if ( $storage->get( $key ) ) {
				return false;
			}

			$storage->set( $key, 1, $max_age );
		}

		return true;
	}

	/**
	 * Per-site secret used for the HMAC.
	 *
	 * @return string
	 */
	private static function secret(): string {
		return wp_salt( 'nonce' );
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `php tests/register-token-test.php`
Expected: 8 `PASS:` lines then `ALL PASSED`, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add includes/Rules/RegisterToken.php tests/register-token-test.php
git commit -m "feat(spam): add RegisterToken with HMAC + timing + single-use, tested"
```

---

## Task 3: RegisterTracker

**Files:**
- Create: `includes/Rules/RegisterTracker.php`

- [ ] **Step 1: Write the implementation**

Create `includes/Rules/RegisterTracker.php` (mirrors `includes/Rules/LoginTracker.php`):

```php
<?php
/**
 * Rejected-registration tracking (spam auto-ban).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\Logger;
use LightweightPlugins\Firewall\Options;
use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Counts rejected registration attempts per IP and bans the IP once the
 * configured threshold is reached within the ban-duration window. The ban is
 * written to the shared firewall ban store (via AutoBanner) so the MU-plugin
 * worker blocks every subsequent request from that IP before WordPress loads.
 */
final class RegisterTracker {

	/**
	 * Storage backend.
	 *
	 * @var StorageInterface
	 */
	private StorageInterface $storage;

	/**
	 * Constructor.
	 *
	 * @param StorageInterface $storage Storage backend.
	 */
	public function __construct( StorageInterface $storage ) {
		$this->storage = $storage;
	}

	/**
	 * Hook-friendly entry point: skip whitelisted IPs, resolve storage and
	 * record the rejection.
	 *
	 * @return void
	 */
	public static function record_reject(): void {
		$ip        = IpDetector::get_ip();
		$whitelist = (array) Options::get( 'ip_whitelist', [] );

		if ( ! empty( $whitelist ) && IpMatcher::matches( $ip, $whitelist ) ) {
			return;
		}

		$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		( new self( $storage ) )->record();
	}

	/**
	 * Record a rejected registration for the current IP and ban it once the
	 * threshold is reached.
	 *
	 * @return void
	 */
	public function record(): void {
		$ip        = IpDetector::get_ip();
		$threshold = (int) Options::get( 'register_ban_threshold', 3 );
		$duration  = (int) Options::get( 'register_ban_duration', 3600 );

		$count = $this->storage->increment( 'register_reject_' . $ip, $duration );

		if ( $count < $threshold ) {
			return;
		}

		( new AutoBanner( $this->storage ) )->ban( $ip, $duration );

		if ( ! empty( Options::get( 'log_enabled' ) ) ) {
			Logger::log(
				[
					'ip'     => $ip,
					'reason' => 'register_spam',
					'ua'     => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 ),
					'url'    => sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ),
				]
			);
		}
	}
}
```

- [ ] **Step 2: Verify PHP parses**

Run: `php -l includes/Rules/RegisterTracker.php`
Expected: `No syntax errors detected`

- [ ] **Step 3: Commit**

```bash
git add includes/Rules/RegisterTracker.php
git commit -m "feat(spam): add RegisterTracker (reject counter -> auto-ban)"
```

---

## Task 4: RegisterGuard

**Files:**
- Create: `includes/Rules/RegisterGuard.php`

- [ ] **Step 1: Write the implementation**

Create `includes/Rules/RegisterGuard.php`:

```php
<?php
/**
 * Registration spam guard: injects and validates the proof-of-render token
 * plus an optional honeypot on the default WordPress registration form.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Options;
use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks `register_form` (inject fields) and `registration_errors` (validate).
 * Only loaded when register protection is enabled and registration is open.
 */
final class RegisterGuard {

	/**
	 * Hidden token field name.
	 */
	private const TOKEN_FIELD = 'lw_fw_reg_token';

	/**
	 * Honeypot field name (must look innocuous to bots).
	 */
	private const HONEYPOT_FIELD = 'lw_fw_url';

	/**
	 * Inject the token (and honeypot) into the rendered registration form.
	 *
	 * @return void
	 */
	public static function render_fields(): void {
		printf(
			'<input type="hidden" name="%s" value="%s" />',
			esc_attr( self::TOKEN_FIELD ),
			esc_attr( RegisterToken::issue() )
		);

		if ( empty( Options::get( 'register_honeypot' ) ) ) {
			return;
		}

		printf(
			'<p style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true"><label>%s<input type="text" name="%s" tabindex="-1" autocomplete="off" value="" /></label></p>',
			esc_html__( 'Leave this field empty', 'lw-firewall' ),
			esc_attr( self::HONEYPOT_FIELD )
		);
	}

	/**
	 * Validate the registration; reject and record spam on any failed check.
	 *
	 * @param WP_Error $errors Registration errors object.
	 * @param string   $login  Sanitized user login (unused).
	 * @param string   $email  User email (unused).
	 * @return WP_Error
	 */
	public static function validate( WP_Error $errors, string $login = '', string $email = '' ): WP_Error { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		if ( self::is_spam() ) {
			RegisterTracker::record_reject();
			$errors->add( 'lw_fw_spam', __( 'Registration failed, please try again.', 'lw-firewall' ) );
		}

		return $errors;
	}

	/**
	 * Run the spam checks (honeypot, then token + timing + single-use).
	 *
	 * @return bool True when the submission looks like spam.
	 */
	private static function is_spam(): bool {
		if ( ! empty( Options::get( 'register_honeypot' ) ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only spam check on the core registration POST; no state change.
			$honeypot = isset( $_POST[ self::HONEYPOT_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::HONEYPOT_FIELD ] ) ) : '';

			if ( '' !== $honeypot ) {
				return true;
			}
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only spam check on the core registration POST; no state change.
		$token = isset( $_POST[ self::TOKEN_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::TOKEN_FIELD ] ) ) : '';

		if ( '' === $token ) {
			return true;
		}

		$min_fill = (int) Options::get( 'register_min_fill_time', 2 );
		$max_age  = (int) Options::get( 'register_token_max_age', 3600 );
		$storage  = null;

		if ( ! empty( Options::get( 'register_single_use' ) ) ) {
			$storage = lw_firewall_resolve_storage( (string) Options::get( 'storage', 'auto' ) );
		}

		return ! RegisterToken::verify( $token, $min_fill, $max_age, $storage );
	}
}
```

- [ ] **Step 2: Verify PHP parses**

Run: `php -l includes/Rules/RegisterGuard.php`
Expected: `No syntax errors detected`

- [ ] **Step 3: Commit**

```bash
git add includes/Rules/RegisterGuard.php
git commit -m "feat(spam): add RegisterGuard (token + honeypot inject/validate)"
```

---

## Task 5: Spam settings tab (SpamFields + TabSpam)

**Files:**
- Create: `includes/Admin/Settings/SpamFields.php`
- Create: `includes/Admin/Settings/TabSpam.php`

- [ ] **Step 1: Create the field definitions**

Create `includes/Admin/Settings/SpamFields.php`:

```php
<?php
/**
 * Field definitions for the Spam settings tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provides the row definitions rendered by TabSpam. Kept separate so the tab
 * class stays a thin renderer and these arrays remain easy to scan/edit.
 */
final class SpamFields {

	/**
	 * Registration protection: enable toggle + token/honeypot tuning.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function registration(): array {
		return [
			'register_protect_enabled' => [
				'th'    => __( 'Enable Registration Protection', 'lw-firewall' ),
				'label' => __( 'Block bot registrations on wp-login.php?action=register', 'lw-firewall' ),
				'desc'  => __( 'Adds a signed proof-of-render token and honeypot to the registration form. Only active when "Anyone can register" is enabled.', 'lw-firewall' ),
			],
			'register_honeypot'        => [
				'th'    => __( 'Honeypot', 'lw-firewall' ),
				'label' => __( 'Add a hidden honeypot field', 'lw-firewall' ),
				'desc'  => __( 'Catches generic bots that fill every field. Invisible to real users.', 'lw-firewall' ),
			],
			'register_single_use'      => [
				'th'    => __( 'Single-Use Token', 'lw-firewall' ),
				'label' => __( 'Reject reused tokens', 'lw-firewall' ),
				'desc'  => __( 'Stores used tokens in the firewall storage backend so each rendered form can register only once.', 'lw-firewall' ),
			],
			'register_min_fill_time'   => [
				'type' => 'number',
				'th'   => __( 'Minimum Fill Time', 'lw-firewall' ),
				'min'  => 0,
				'max'  => 60,
				'desc' => __( 'Reject submissions faster than this many seconds after the form loaded (catches instant bot POSTs).', 'lw-firewall' ),
			],
			'register_token_max_age'   => [
				'type' => 'number',
				'th'   => __( 'Token Lifetime', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'How long a rendered form stays valid, in seconds (3600 = 1 hour).', 'lw-firewall' ),
			],
		];
	}

	/**
	 * Registration auto-ban: threshold + duration.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function auto_ban(): array {
		return [
			'register_ban_threshold' => [
				'type' => 'number',
				'th'   => __( 'Ban Threshold', 'lw-firewall' ),
				'min'  => 2,
				'max'  => 100,
				'desc' => __( 'Number of rejected registrations from one IP before it is banned.', 'lw-firewall' ),
			],
			'register_ban_duration'  => [
				'type' => 'number',
				'th'   => __( 'Ban Duration', 'lw-firewall' ),
				'min'  => 60,
				'max'  => 86400,
				'desc' => __( 'How long the ban lasts in seconds (3600 = 1 hour).', 'lw-firewall' ),
			],
		];
	}
}
```

- [ ] **Step 2: Create the tab renderer**

Create `includes/Admin/Settings/TabSpam.php` (mirrors `TabProtection`):

```php
<?php
/**
 * Spam Settings Tab.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Admin\Settings;

/**
 * Spam tab: registration spam protection (proof-of-render token, honeypot,
 * auto-ban).
 */
final class TabSpam implements TabInterface {

	use FieldRendererTrait;

	/**
	 * Get the tab slug.
	 */
	public function get_slug(): string {
		return 'spam';
	}

	/**
	 * Get the tab label.
	 */
	public function get_label(): string {
		return __( 'Spam', 'lw-firewall' );
	}

	/**
	 * Get the tab icon.
	 */
	public function get_icon(): string {
		return 'dashicons-shield-alt';
	}

	/**
	 * Render the tab content.
	 */
	public function render(): void {
		$this->render_section(
			__( 'Registration Protection', 'lw-firewall' ),
			__( 'Block bot sign-ups on wp-login.php?action=register without a captcha. Active only when "Anyone can register" is enabled in Settings → General.', 'lw-firewall' ),
			SpamFields::registration()
		);

		$this->render_section(
			__( 'Registration Auto-Ban', 'lw-firewall' ),
			__( 'Ban IPs that repeatedly submit spam registrations. A banned IP is blocked from the whole site, not just the registration form.', 'lw-firewall' ),
			SpamFields::auto_ban()
		);
	}

	/**
	 * Render a settings section: heading, intro and a form-table of rows.
	 *
	 * @param string                              $heading Section heading.
	 * @param string                              $intro   Section description.
	 * @param array<string, array<string, mixed>> $rows    Field rows keyed by option name.
	 */
	private function render_section( string $heading, string $intro, array $rows ): void {
		?>
		<h2><?php echo esc_html( $heading ); ?></h2>
		<p class="lw-firewall-section-description"><?php echo esc_html( $intro ); ?></p>

		<table class="form-table">
			<?php
			foreach ( $rows as $name => $row ) {
				$this->render_row( $name, $row );
			}
			?>
		</table>
		<?php
	}

	/**
	 * Render a single form-table row (checkbox by default, number when typed).
	 *
	 * @param string               $name Option name.
	 * @param array<string, mixed> $row  Row config (th, label, desc, type, min, max).
	 */
	private function render_row( string $name, array $row ): void {
		?>
		<tr>
			<th scope="row"><?php echo esc_html( (string) ( $row['th'] ?? $row['label'] ?? '' ) ); ?></th>
			<td>
				<?php
				if ( 'number' === ( $row['type'] ?? '' ) ) {
					$this->render_number_field(
						[
							'name'        => $name,
							'min'         => (int) $row['min'],
							'max'         => (int) $row['max'],
							'description' => (string) $row['desc'],
						]
					);
				} else {
					$this->render_checkbox_field(
						[
							'name'        => $name,
							'label'       => (string) $row['label'],
							'description' => (string) $row['desc'],
						]
					);
				}
				?>
			</td>
		</tr>
		<?php
	}
}
```

- [ ] **Step 3: Verify PHP parses**

Run: `php -l includes/Admin/Settings/SpamFields.php && php -l includes/Admin/Settings/TabSpam.php`
Expected: `No syntax errors detected` for both.

- [ ] **Step 4: Commit**

```bash
git add includes/Admin/Settings/SpamFields.php includes/Admin/Settings/TabSpam.php
git commit -m "feat(spam): add Spam settings tab and field definitions"
```

---

## Task 6: Persist the new options in SettingsSaver

**Files:**
- Modify: `includes/Admin/SettingsSaver.php` (inside `save_options()`, after the `$values['login_lockout_duration']` block, before the `$values['action']` block)

- [ ] **Step 1: Add the register_* values**

In `includes/Admin/SettingsSaver.php`, find:

```php
		$values['login_lockout_duration'] = isset( $post_data['login_lockout_duration'] )
			? absint( $post_data['login_lockout_duration'] )
			: $current['login_lockout_duration'];
```

Insert immediately after it:

```php
		$values['register_protect_enabled'] = ! empty( $post_data['register_protect_enabled'] );
		$values['register_honeypot']        = ! empty( $post_data['register_honeypot'] );
		$values['register_single_use']      = ! empty( $post_data['register_single_use'] );

		$values['register_min_fill_time'] = isset( $post_data['register_min_fill_time'] )
			? absint( $post_data['register_min_fill_time'] )
			: $current['register_min_fill_time'];

		$values['register_token_max_age'] = isset( $post_data['register_token_max_age'] )
			? absint( $post_data['register_token_max_age'] )
			: $current['register_token_max_age'];

		$values['register_ban_threshold'] = isset( $post_data['register_ban_threshold'] )
			? absint( $post_data['register_ban_threshold'] )
			: $current['register_ban_threshold'];

		$values['register_ban_duration'] = isset( $post_data['register_ban_duration'] )
			? absint( $post_data['register_ban_duration'] )
			: $current['register_ban_duration'];
```

- [ ] **Step 2: Verify PHP parses**

Run: `php -l includes/Admin/SettingsSaver.php`
Expected: `No syntax errors detected`

- [ ] **Step 3: Commit**

```bash
git add includes/Admin/SettingsSaver.php
git commit -m "feat(spam): persist registration spam options on save"
```

---

## Task 7: Register the tab and wire the hooks

**Files:**
- Modify: `includes/Admin/SettingsPage.php` (add `use` + `$tabs` entry)
- Modify: `includes/Plugin.php` (add `use` + hook block)

- [ ] **Step 1: Add the TabSpam use + tab entry**

In `includes/Admin/SettingsPage.php`, find:

```php
use LightweightPlugins\Firewall\Admin\Settings\TabSecurity;
```

Insert after it:

```php
use LightweightPlugins\Firewall\Admin\Settings\TabSpam;
```

Then find:

```php
			new TabProtection(),
			new TabBots(),
```

Change to:

```php
			new TabProtection(),
			new TabSpam(),
			new TabBots(),
```

- [ ] **Step 2: Add the RegisterGuard use in Plugin.php**

In `includes/Plugin.php`, find:

```php
use LightweightPlugins\Firewall\Rules\NotFoundTracker;
```

Insert after it:

```php
use LightweightPlugins\Firewall\Rules\RegisterGuard;
```

- [ ] **Step 3: Wire the register hooks**

In `includes/Plugin.php`, inside `init_runtime_hooks()`, find:

```php
		// Brute-force login protection.
		if ( ! empty( $options['login_limit_enabled'] ) ) {
			add_action( 'wp_login_failed', [ $this, 'track_failed_login' ] );
		}
```

Insert immediately after that block:

```php
		// Registration spam protection (default WP register form only).
		if ( ! empty( $options['register_protect_enabled'] ) && get_option( 'users_can_register' ) ) {
			add_action( 'register_form', [ RegisterGuard::class, 'render_fields' ] );
			add_filter( 'registration_errors', [ RegisterGuard::class, 'validate' ], 10, 3 );
		}
```

- [ ] **Step 4: Verify PHP parses**

Run: `php -l includes/Admin/SettingsPage.php && php -l includes/Plugin.php`
Expected: `No syntax errors detected` for both.

- [ ] **Step 5: Commit**

```bash
git add includes/Admin/SettingsPage.php includes/Plugin.php
git commit -m "feat(spam): register Spam tab and wire registration hooks"
```

---

## Task 8: Version bump to 1.4.0

**Files:**
- Modify: `lw-firewall.php` (header `Version:` + `LW_FIREWALL_VERSION`)
- Modify: `worker/lw-firewall-worker.php` (`@version` + `LW_FIREWALL_WORKER_VERSION`)
- Modify: `readme.txt` (`Stable tag:` + Changelog entry)
- Modify: `CHANGELOG.md` (new entry)

- [ ] **Step 1: Bump lw-firewall.php**

In `lw-firewall.php`, change `* Version:     1.3.0` to `* Version:     1.4.0`, and change `define( 'LW_FIREWALL_VERSION', '1.3.0' );` to `define( 'LW_FIREWALL_VERSION', '1.4.0' );`.

- [ ] **Step 2: Bump worker/lw-firewall-worker.php**

In `worker/lw-firewall-worker.php`, change ` * @version 1.3.0` to ` * @version 1.4.0`, and change `define( 'LW_FIREWALL_WORKER_VERSION', '1.3.0' );` to `define( 'LW_FIREWALL_WORKER_VERSION', '1.4.0' );`.

- [ ] **Step 3: Bump readme.txt stable tag + changelog**

In `readme.txt`, change `Stable tag: 1.3.0` to `Stable tag: 1.4.0`. Then find `== Changelog ==` and insert immediately below it:

```
= 1.4.0 =
* New: Registration spam protection — signed proof-of-render token + honeypot on wp-login.php?action=register, blocking bot sign-ups without a captcha
* New: Spam settings tab with token timing, single-use enforcement, and per-IP auto-ban for repeated spam registrations
```

- [ ] **Step 4: Add CHANGELOG.md entry**

In `CHANGELOG.md`, find `# Changelog` and insert immediately below it:

```markdown

## [1.4.0] - 2026-06-12

### Added
- Registration spam protection for `wp-login.php?action=register`. A signed proof-of-render token (HMAC over `wp_salt('nonce')` + issue time) plus an optional honeypot reject bots — including WordPress-aware bots that POST directly without rendering the form. Token checks cover timing (too-fast submits), expiry, and optional single-use via the firewall storage backend
- New `RegisterTracker` counts rejected registrations per IP and bans repeat offenders through the shared ban store, so the MU-plugin worker blocks them before WordPress loads
- New Spam settings tab exposing the master toggle, honeypot, single-use, minimum fill time, token lifetime, ban threshold, and ban duration. Disabled by default; only active when "Anyone can register" is enabled; whitelisted IPs are never counted
```

- [ ] **Step 5: Verify versions match**

Run: `grep -rn "1.4.0" lw-firewall.php worker/lw-firewall-worker.php readme.txt CHANGELOG.md`
Expected: the four version locations (plus `@version`, both constants, stable tag) all show `1.4.0`; no remaining `1.3.0` in the plugin header / worker version constant.

- [ ] **Step 6: Commit**

```bash
git add lw-firewall.php worker/lw-firewall-worker.php readme.txt CHANGELOG.md
git commit -m "Bump to 1.4.0 - registration spam protection"
```

---

## Task 9: Lint and full test pass

- [ ] **Step 1: Run PHPCS**

Run: `composer phpcs`
Expected: no errors. If there are errors, run `composer phpcbf`, then `composer phpcs` again, and fix anything auto-fix could not.

- [ ] **Step 2: Run the token test**

Run: `php tests/register-token-test.php`
Expected: `ALL PASSED`, exit code 0.

- [ ] **Step 3: Commit any phpcbf fixes**

```bash
git add -A
git commit -m "style: phpcs fixes for registration spam protection"
```

(Skip this commit if `composer phpcbf` changed nothing.)

---

## Manual verification (after merge, on a test site)

Not automatable here; documented for the implementer/reviewer:

1. Settings → General → enable "Anyone can register". In the firewall Spam tab, enable Registration Protection. Save.
2. Visit `wp-login.php?action=register`, register a real account slowly → succeeds.
3. `curl -X POST` directly to `wp-login.php?action=register` with only `user_login` + `user_email` (no token) → registration rejected.
4. Repeat the direct POST `register_ban_threshold` times → the IP gets a 403 from the worker on the next request.
5. Confirm WooCommerce / custom registration flows are unaffected (different hooks).

---

## Notes

- **Spec correction:** the design spec said `SettingsSaver` needed no change because it "iterates `get_defaults()` keys". That is wrong — `save_options()` lists every key explicitly. Task 6 adds the register keys; without it the toggles never persist.
- **Counting window:** `RegisterTracker` uses `register_ban_duration` as both the ban length and the rejection-counting window (the `increment` TTL), avoiding an extra option. This matches the lightweight intent; revisit only if a separate window is requested.
- **No worker logic change:** the worker is bumped only to satisfy the version-guard/CI lockstep check; registration protection runs entirely in normal WordPress.
```
