<?php
/**
 * Server-side value policy for every option.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One place that decides what a setting is allowed to hold.
 *
 * The admin form, WP-CLI and the settings import each used to apply their own
 * partial policy: the form trusted the HTML `min`/`max` attributes, which are a
 * client-side hint and nothing more, and none of the three checked that an
 * enum-valued setting held one of its enum values. A typo, a hand-written JSON
 * import or an automation script could therefore write a number the runtime
 * treats as "never expire", or an action string that matches no branch.
 */
final class OptionSchema {

	/**
	 * Numeric bounds, keyed by option. Values outside the range are clamped.
	 *
	 * @return array<string, array{0: int, 1: int}>
	 */
	public static function ranges(): array {
		return [
			'rate_limit'             => [ 1, 100000 ],
			'rate_window'            => [ 1, 86400 ],
			'auto_ban_threshold'     => [ 1, 1000 ],
			'auto_ban_duration'      => [ 60, 2592000 ],
			'login_max_attempts'     => [ 1, 1000 ],
			'login_lockout_window'   => [ 60, 86400 ],
			'login_lockout_duration' => [ 60, 2592000 ],
			'register_min_fill_time' => [ 1, 3600 ],
			'register_token_max_age' => [ 60, 86400 ],
			'register_ban_threshold' => [ 1, 1000 ],
			'register_ban_duration'  => [ 60, 2592000 ],
			'reset_ip_max'           => [ 0, 100000 ],
			'reset_ip_window'        => [ 60, 86400 ],
			'reset_user_max'         => [ 0, 100000 ],
			'reset_user_window'      => [ 60, 86400 ],
			'reset_global_max'       => [ 0, 1000000 ],
			'reset_min_fill_time'    => [ 1, 3600 ],
			'reset_token_max_age'    => [ 60, 86400 ],
			'reset_ban_duration'     => [ 60, 2592000 ],
		];
	}

	/**
	 * Allowed values for the settings that are enums.
	 *
	 * @return array<string, array<int, string>>
	 */
	public static function enums(): array {
		return [
			'storage'      => [ 'auto', 'apcu', 'redis', 'file' ],
			'action'       => [ 'redirect', '429' ],
			'proxy_header' => [ 'x-forwarded-for', 'x-real-ip', 'forwarded' ],
		];
	}

	/**
	 * Apply the policy to one value.
	 *
	 * Pure — no WordPress calls — so the rules are unit testable and identical
	 * for every ingress.
	 *
	 * @param string $key      Option key.
	 * @param mixed  $value    Candidate value.
	 * @param mixed  $fallback Value to keep when the candidate is unusable.
	 * @return mixed
	 */
	public static function apply( string $key, mixed $value, mixed $fallback = null ): mixed {
		$ranges = self::ranges();

		if ( isset( $ranges[ $key ] ) ) {
			[ $min, $max ] = $ranges[ $key ];

			return max( $min, min( $max, (int) $value ) );
		}

		$enums = self::enums();

		if ( isset( $enums[ $key ] ) ) {
			$candidate = is_scalar( $value ) ? strtolower( trim( (string) $value ) ) : '';

			return in_array( $candidate, $enums[ $key ], true ) ? $candidate : $fallback;
		}

		return $value;
	}

	/**
	 * Apply the policy to a whole configuration array.
	 *
	 * @param array<string, mixed> $values    Candidate values.
	 * @param array<string, mixed> $fallbacks Values to keep where a candidate is unusable.
	 * @return array<string, mixed>
	 */
	public static function apply_all( array $values, array $fallbacks = [] ): array {
		foreach ( $values as $key => $value ) {
			$values[ $key ] = self::apply( $key, $value, $fallbacks[ $key ] ?? null );
		}

		return $values;
	}
}
