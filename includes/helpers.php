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
	// Memoized per request. Every call used to re-run the availability probes
	// and open a fresh connection, so a page that touched storage from several
	// rules paid for several Redis handshakes — on the hot path, before the
	// request was even classified.
	static $resolved = [];

	if ( isset( $resolved[ $preference ] ) ) {
		return $resolved[ $preference ];
	}

	$resolved[ $preference ] = lw_firewall_build_storage( $preference );

	return $resolved[ $preference ];
}

/**
 * Build a storage backend for the given preference.
 *
 * @param string $preference 'auto' | 'apcu' | 'redis' | 'file'.
 * @return LightweightPlugins\Firewall\Storage\StorageInterface
 */
function lw_firewall_build_storage( string $preference ): LightweightPlugins\Firewall\Storage\StorageInterface {
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
	// Accepted trade, not an oversight: the worker runs before WordPress can
	// validate an auth cookie, so this recognises one by shape only. Anyone can
	// forge that shape and obtain the higher REST/filter bucket. The cost is
	// bounded — login, xmlrpc and cron stay fully throttled regardless, and
	// abuse in the raised bucket is still recorded for auto-ban — and the
	// alternative is either no headroom for signed-in dashboards or booting
	// WordPress before every request is classified.

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
 * Split a request URI into a decoded path and its query arguments.
 *
 * Endpoint detection used to run str_contains() over the raw URI, so the query
 * string could impersonate a path: "/wp-json/x?next=/wp-cron.php" classified as
 * cron, and an innocent "?redirect=/wp-login.php" was billed to the login
 * quota. Path and query are separated once, here, and compared exactly.
 *
 * @param string $uri Request URI (path plus query string).
 * @return array{path: string, args: array<string, string>}
 */
function lw_firewall_parse_uri( string $uri ): array {
	$path  = (string) strtok( $uri, '?' );
	$query = (string) substr( $uri, strlen( $path ) + 1 );

	// A percent-encoded separator must not hide an endpoint from an exact
	// comparison; decoding before matching closes that.
	$path = rawurldecode( $path );

	// Collapse repeated slashes and strip a trailing one so "//wp-cron.php" and
	// "/wp-cron.php/" cannot dodge an exact match.
	$path = (string) preg_replace( '#/+#', '/', $path );

	if ( '/' !== $path ) {
		$path = rtrim( $path, '/' );
	}

	$args = [];

	if ( '' !== $query ) {
		parse_str( $query, $args );
	}

	return [
		'path' => '' === $path ? '/' : $path,
		'args' => array_map( static fn ( $v ): string => is_scalar( $v ) ? (string) $v : '', $args ),
	];
}

/**
 * Whether a parsed request is one of WordPress's own WP-Cron loopbacks.
 *
 * WordPress's spawn_cron() always calls wp-cron.php with a ?doing_wp_cron=
 * timestamp.
 * Recognising it exempts scheduled work (e.g. WooCommerce Analytics imports via
 * Action Scheduler) from cron rate limiting, while a bare "GET /wp-cron.php" —
 * the usual DoS trigger — stays throttled.
 *
 * The marker is only honoured on the cron path itself (wherever the install
 * lives, e.g. "/blog/wp-cron.php"). Accepting it anywhere let any request opt
 * out of classification entirely by appending it.
 *
 * @param array{path: string, args: array<string, string>} $request Parsed request.
 * @return bool
 */
function lw_firewall_is_cron_loopback( array $request ): bool {
	return lw_firewall_path_is( $request['path'], '/wp-cron.php' ) && isset( $request['args']['doing_wp_cron'] );
}

/**
 * Whether a request path addresses a given WordPress endpoint script.
 *
 * The endpoint must appear as a whole path segment — right after a "/" and
 * followed by the end of the path or another "/" — compared case-insensitively.
 * That covers:
 * - a subdirectory install's "/blog/wp-login.php";
 * - PATH_INFO ("/wp-login.php/x"), where the web server still runs the script;
 * - case variants ("/XMLRPC.php") that case-insensitive filesystems serve.
 * A look-alike file ("/foo-wp-login.php", "/wp-login.php.bak") or a query
 * argument that merely mentions the filename does not match.
 *
 * @param string $path     Decoded request path.
 * @param string $endpoint Endpoint path, e.g. "/wp-login.php".
 * @return bool
 */
function lw_firewall_path_is( string $path, string $endpoint ): bool {
	return 1 === preg_match( '#' . preg_quote( $endpoint, '#' ) . '(?:/|$)#i', $path );
}

/**
 * Detect request type from URI.
 *
 * Returns an array of [reason, custom_limit]. The custom_limit is null unless
 * a filter param entry specifies one (e.g. "filter_|30").
 *
 * @param string               $uri     Request URI.
 * @param array<string, mixed> $options Plugin options.
 * @return array{0: string|null, 1: int|null}
 */
function lw_firewall_detect_type( string $uri, array $options ): array {
	$request = lw_firewall_parse_uri( $uri );
	$path    = $request['path'];

	// Endpoints are matched on the decoded path only. The query string is a
	// place a client can write anything, so letting it name an endpoint both
	// exempted crafted requests and billed innocent ones to the wrong quota.
	if ( lw_firewall_path_is( $path, '/wp-cron.php' ) && ! empty( $options['protect_cron'] ) ) {
		// Never throttle WordPress's own cron loopback (?doing_wp_cron=…) — that
		// would stall scheduled work such as WooCommerce Analytics imports. A
		// bare GET /wp-cron.php (the common DoS trigger) is still rate-limited.
		if ( lw_firewall_is_cron_loopback( $request ) ) {
			return [ null, null ];
		}

		return [ 'cron', null ];
	}

	if ( lw_firewall_path_is( $path, '/xmlrpc.php' ) && ! empty( $options['protect_xmlrpc'] ) ) {
		return [ 'xmlrpc', null ];
	}

	if ( lw_firewall_path_is( $path, '/wp-login.php' ) && ! empty( $options['protect_login'] ) ) {
		return [ 'login', null ];
	}

	// Both REST shapes: the pretty /wp-json/ prefix and the ?rest_route= form
	// that works even when pretty permalinks are off.
	if ( ! empty( $options['protect_rest_api'] )
		&& ( str_contains( $path . '/', '/wp-json/' ) || isset( $request['args']['rest_route'] ) )
	) {
		return [ 'rest', null ];
	}

	// WooCommerce filter parameter detection.
	// Entries may include a custom rate limit: "filter_|30".
	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
	$query_string  = $_SERVER['QUERY_STRING'] ?? '';
	$filter_params = (array) ( $options['filter_params'] ?? [ 'filter_|30', 'query_type_|30' ] );

	if ( '' !== $query_string ) {
		$matched      = false;
		$custom_limit = null;

		foreach ( $filter_params as $entry ) {
			$parts  = explode( '|', (string) $entry, 2 );
			$prefix = $parts[0];

			if ( str_contains( $query_string, $prefix ) ) {
				$matched = true;

				// Use the lowest custom limit if multiple params match.
				if ( isset( $parts[1] ) && is_numeric( $parts[1] ) ) {
					$limit        = (int) $parts[1];
					$custom_limit = ( null === $custom_limit ) ? $limit : min( $custom_limit, $limit );
				}
			}
		}

		if ( $matched ) {
			return [ 'filter', $custom_limit ];
		}
	}

	return [ null, null ];
}

/**
 * Log a firewall event if logging is enabled.
 *
 * @param array<string, mixed> $options Plugin options.
 * @param string               $ip      Client IP.
 * @param string               $reason  Block reason.
 */
function lw_firewall_log( array $options, string $ip, string $reason ): void {
	if ( empty( $options['log_enabled'] ) ) {
		return;
	}

	\LightweightPlugins\Firewall\Logger::log(
		[
			'ip'     => $ip,
			'reason' => $reason,
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			// Sanitized like every other log producer: an unauthenticated client
			// must not be able to write control bytes or invalid UTF-8 into the option.
			'ua'     => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 200 ),
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			'url'    => sanitize_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ) ),
		]
	);
}

/**
 * Check if the IP belongs to the server itself.
 *
 * Matches localhost, server address, and the site domain's resolved IP
 * (cached for 5 minutes to avoid DNS lookups on every request).
 *
 * @param string $ip Client IP to check.
 * @return bool
 */
function lw_firewall_is_server_ip( string $ip ): bool {
	// Localhost.
	if ( '127.0.0.1' === $ip || '::1' === $ip ) {
		return true;
	}

	// Server's own IP.
	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
	$server_addr = $_SERVER['SERVER_ADDR'] ?? '';
	if ( '' !== $server_addr && $server_addr === $ip ) {
		return true;
	}

	// The site's own hostname is deliberately NOT resolved here. SERVER_NAME
	// comes from the client's Host header under Apache's default
	// UseCanonicalName Off, so resolving it handed an attacker a full firewall
	// exemption for any address they could make a hostname point at — cached
	// for five minutes on top.
	return false;
}

/**
 * Send 403 Forbidden and exit.
 */
function lw_firewall_block_403(): void {
	if ( ! headers_sent() ) {
		header( 'HTTP/1.1 403 Forbidden' );
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'Cache-Control: no-store, no-cache' );
	}

	echo 'Access denied.';
	exit;
}
