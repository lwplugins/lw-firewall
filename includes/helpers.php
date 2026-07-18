<?php
/**
 * Shared helper functions used by both the main plugin and the MU-plugin worker.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolve the storage backend instance.
 *
 * @param string $preference Storage preference ('auto', 'apcu', 'redis', 'file').
 * @return LightweightPlugins\Firewall\Storage\StorageInterface
 */
function lw_firewall_resolve_storage( string $preference ): LightweightPlugins\Firewall\Storage\StorageInterface {
	if ( 'apcu' === $preference && LightweightPlugins\Firewall\Storage\ApcuStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\ApcuStorage();
	}

	if ( 'redis' === $preference && LightweightPlugins\Firewall\Storage\RedisStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\RedisStorage();
	}

	if ( 'file' === $preference ) {
		return new LightweightPlugins\Firewall\Storage\FileStorage();
	}

	// Auto-detect: apcu > redis > file.
	if ( LightweightPlugins\Firewall\Storage\ApcuStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\ApcuStorage();
	}

	if ( LightweightPlugins\Firewall\Storage\RedisStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\RedisStorage();
	}

	return new LightweightPlugins\Firewall\Storage\FileStorage();
}

/**
 * Detect a WordPress logged-in session from the request cookies.
 *
 * Runs inside the MU-plugin worker at muplugins_loaded, long before WordPress
 * authentication is available, so is_user_logged_in() cannot be used. We look
 * for the logged-in cookie (WordPress sets it at path "/", so it is present on
 * /wp-json/ REST requests too) and require the WP auth-cookie shape
 * (user|expiration|token|hmac) to reject trivially-shaped junk values.
 *
 * This is intentionally NOT a cryptographic check, and it is only ever used to
 * route a request into a separate, higher-limit bucket on the REST/filter
 * endpoints (see lw_firewall_login_exempt_reason()) — never to fully exempt it.
 * A forged cookie therefore only raises the limit on those two endpoints; every
 * hard block (IP blacklist, geo, auto-ban, 404 flood, bot) and the login /
 * xmlrpc / cron throttles still apply in full.
 *
 * @return bool True when the request carries a plausible WordPress logged-in cookie.
 */
function lw_firewall_has_login_cookie(): bool {
	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- cookie name/shape only, no value trust.
	foreach ( $_COOKIE as $name => $value ) {
		if ( str_starts_with( (string) $name, 'wordpress_logged_in_' )
			&& substr_count( (string) $value, '|' ) >= 3
		) {
			return true;
		}
	}

	return false;
}

/**
 * Whether a rate-limit reason may use the logged-in (higher-limit) bucket.
 *
 * Only REST and WooCommerce-filter requests suffer logged-in false positives —
 * admin dashboards (wc-admin, Gutenberg, media) fire request bursts against
 * /wp-json/ and filtered archive URLs. The login, xmlrpc and cron throttles are
 * abuse surfaces where a signed-in user has no legitimate burst, so they stay
 * fully throttled regardless of any cookie.
 *
 * @param string $reason Detected request type.
 * @return bool
 */
function lw_firewall_login_exempt_reason( string $reason ): bool {
	return 'rest' === $reason || 'filter' === $reason;
}

/**
 * The rate limit applied to a signed-in request on an exempt endpoint.
 *
 * Generous headroom (10× the base limit by default) so real dashboards load,
 * while still capping abuse: a forged cookie flooding /wp-json/ eventually trips
 * this limit and, with auto-ban on, is recorded as a violation. Override with
 * define( 'LW_FIREWALL_LOGGEDIN_MULTIPLIER', N ) in wp-config.php.
 *
 * @param int|null             $custom_limit Endpoint-specific base limit, if any.
 * @param array<string, mixed> $options      Plugin options.
 * @return int
 */
function lw_firewall_loggedin_limit( ?int $custom_limit, array $options ): int {
	$base   = $custom_limit ?? (int) ( $options['rate_limit'] ?? 30 );
	$factor = defined( 'LW_FIREWALL_LOGGEDIN_MULTIPLIER' ) ? (int) LW_FIREWALL_LOGGEDIN_MULTIPLIER : 10;

	return max( 1, $base ) * max( 1, $factor );
}

/**
 * Detect WordPress's own WP-Cron loopback request.
 *
 * WordPress's spawn_cron() always calls wp-cron.php with a ?doing_wp_cron=
 * timestamp query arg. Recognising it lets the worker exempt scheduled work
 * (e.g. WooCommerce Analytics imports run via Action Scheduler) from cron
 * rate-limiting, while a bare "GET /wp-cron.php" — the usual DoS trigger —
 * stays throttled. The path check keeps the marker from being smuggled onto
 * other endpoints to bypass their limits.
 *
 * @param string $uri Request URI (path plus query string).
 * @return bool
 */
function lw_firewall_is_cron_loopback( string $uri ): bool {
	return str_contains( $uri, '/wp-cron.php' ) && str_contains( $uri, 'doing_wp_cron=' );
}
