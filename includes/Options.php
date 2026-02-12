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
	 * Default settings.
	 *
	 * @return array<string, mixed>
	 */
	public static function get_defaults(): array {
		return [
			'enabled'            => true,
			'storage'            => 'auto', // 'auto' | 'apcu' | 'redis' | 'file'.
			'rate_limit'         => 30,
			'rate_window'        => 60,
			'action'             => 'redirect', // 'redirect' | '429'.
			'protect_cron'       => false,
			'protect_xmlrpc'     => false,
			'protect_login'      => true,
			'protect_rest_api'   => false,
			'protect_404'        => false,
			'ip_whitelist'       => [],
			'ip_blacklist'       => [],
			'auto_ban_enabled'   => false,
			'auto_ban_threshold' => 3,
			'auto_ban_duration'  => 3600,
			'security_headers'   => false,
			'blocked_bots'       => [
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
			'log_enabled'        => false,
			'filter_params'      => [ 'filter_', 'query_type_' ],
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

		return array_merge( self::get_defaults(), $saved );
	}

	/**
	 * Save options.
	 *
	 * @param array<string, mixed> $values New values to save.
	 * @return bool
	 */
	public static function save( array $values ): bool {
		$current  = self::get_all();
		$defaults = self::get_defaults();

		// Only save keys that exist in defaults.
		$sanitized = [];
		foreach ( $defaults as $key => $default_value ) {
			if ( array_key_exists( $key, $values ) ) {
				$sanitized[ $key ] = $values[ $key ];
			} else {
				$sanitized[ $key ] = $current[ $key ];
			}
		}

		return update_option( self::OPTION_NAME, $sanitized );
	}
}
