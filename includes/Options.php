<?php
/**
 * Plugin options management.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles reading, writing and defaulting of plugin settings.
 */
final class Options {

	public const OPTION_NAME = 'lw_firewall';

	/**
	 * Option keys whose stored value must be an array. These get coerced on
	 * read so any historical bad data (e.g. textarea content saved as a
	 * single string with newlines) still produces a usable list — the
	 * worker, admin, and CLI all see arrays.
	 *
	 * @var array<int, string>
	 */
	private const LIST_KEYS = [
		'filter_params',
		'blocked_bots',
		'ip_whitelist',
		'ip_blacklist',
		'blocked_countries',
	];

	/**
	 * Default settings.
	 *
	 * @return array<string, mixed>
	 */
	public static function get_defaults(): array {
		return [
			'enabled'                  => true,
			'storage'                  => 'auto', // 'auto' | 'apcu' | 'redis' | 'file'.
			'rate_limit'               => 30,
			'rate_window'              => 60,
			'action'                   => 'redirect', // 'redirect' | '429'.
			'protect_cron'             => false,
			'protect_xmlrpc'           => false,
			'protect_login'            => true,
			'protect_rest_api'         => false,
			'protect_404'              => false,
			'ip_whitelist'             => [],
			'ip_blacklist'             => [],
			'auto_ban_enabled'         => false,
			'auto_ban_threshold'       => 3,
			'auto_ban_duration'        => 3600,
			'login_limit_enabled'      => false,
			'login_max_attempts'       => 5,
			'login_lockout_window'     => 600,
			'login_lockout_duration'   => 3600,
			'register_protect_enabled' => true,
			'register_min_fill_time'   => 2,
			'register_token_max_age'   => 3600,
			'register_honeypot'        => true,
			'register_single_use'      => true,
			'register_ban_threshold'   => 3,
			'register_ban_duration'    => 3600,
			'security_headers'         => false,
			'blocked_bots'             => [
				'meta-externalagent',
				'meta-externalfetcher',
				'gptbot',
				'chatgpt-user',
				'claudebot',
				'claude-web',
				'bytespider',
				'amazonbot',
				'anthropic-ai',
				'cohere-ai',
				'diffbot',
				'perplexitybot',
				'youbot',
				'petalbot',
				'semrushbot',
				'ahrefsbot',
				'dotbot',
				'mj12bot',
				'barkrowler',
				'dataforseobot',
			],
			'log_enabled'              => false,
			'filter_params'            => [ 'filter_|30', 'query_type_|30' ],
			'geo_enabled'              => true,
			'geo_action'               => '403', // '403' | 'redirect'.
			'blocked_countries'        => [ 'CN', 'RU', 'IN', 'VN', 'ID', 'BD' ],
		];
	}

	/**
	 * Get a single option value.
	 *
	 * @param string $key     Option key.
	 * @param mixed  $default Fallback value.
	 * @return mixed
	 */
	public static function get( string $key, mixed $default = null ): mixed {
		// wp-config.php constant override.
		$const = 'LW_FIREWALL_' . strtoupper( $key );
		if ( defined( $const ) ) {
			return constant( $const );
		}

		$options = self::get_all();

		return $options[ $key ] ?? $default ?? self::get_defaults()[ $key ] ?? null;
	}

	/**
	 * Get all options merged with defaults.
	 *
	 * @return array<string, mixed>
	 */
	public static function get_all(): array {
		$saved = get_option( self::OPTION_NAME, [] );

		if ( ! is_array( $saved ) ) {
			$saved = [];
		}

		$merged = array_merge( self::get_defaults(), $saved );

		foreach ( self::LIST_KEYS as $list_key ) {
			if ( isset( $merged[ $list_key ] ) && ! is_array( $merged[ $list_key ] ) ) {
				$merged[ $list_key ] = self::normalize_list( $merged[ $list_key ] );
			}
		}

		return $merged;
	}

	/**
	 * Coerce a non-array list value (typically a string with newlines or
	 * commas) into a clean array of trimmed entries.
	 *
	 * @param mixed $value Stored value.
	 * @return array<int, string>
	 */
	private static function normalize_list( mixed $value ): array {
		if ( ! is_string( $value ) ) {
			return [];
		}

		$parts = preg_split( '/[\r\n,]+/', $value );

		if ( false === $parts ) {
			return [];
		}

		$parts = array_map( 'trim', $parts );
		$parts = array_filter( $parts, static fn ( string $p ): bool => '' !== $p );

		return array_values( $parts );
	}

	/**
	 * Whether a string is a syntactically valid ISO 3166-1 alpha-2 country code.
	 *
	 * Used as a defensive guard everywhere a country code is turned into a file
	 * path (GeoDetector include, CidrUpdater cache write) or an .htaccess rule
	 * (HtaccessWriter), so an attacker-influenced value (e.g. imported from an
	 * untrusted settings JSON) cannot smuggle path traversal or newlines into
	 * those sinks.
	 *
	 * @param string $code Candidate code.
	 * @return bool
	 */
	public static function is_country_code( string $code ): bool {
		return 1 === preg_match( '/^[A-Za-z]{2}$/', $code );
	}

	/**
	 * Reduce a raw list to valid, unique, uppercase country codes.
	 *
	 * @param array<int|string, mixed> $codes Raw codes.
	 * @return array<int, string>
	 */
	public static function sanitize_country_codes( array $codes ): array {
		$clean = [];

		foreach ( $codes as $code ) {
			$code = strtoupper( trim( (string) $code ) );

			if ( self::is_country_code( $code ) ) {
				$clean[] = $code;
			}
		}

		return array_values( array_unique( $clean ) );
	}

	/**
	 * Save options.
	 *
	 * @param array<string, mixed> $values New values to save.
	 * @return bool
	 */
	public static function save( array $values ): bool {
		$current   = self::get_all();
		$sanitized = [];

		foreach ( array_keys( self::get_defaults() ) as $key ) {
			$sanitized[ $key ] = array_key_exists( $key, $values ) ? $values[ $key ] : $current[ $key ];
		}

		return update_option( self::OPTION_NAME, $sanitized );
	}
}
