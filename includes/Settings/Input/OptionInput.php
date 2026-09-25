<?php
/**
 * The single input layer for every settings ingress.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Settings\Input;

use LightweightPlugins\Firewall\OptionSchema;
use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns raw submitted values into option values.
 *
 * The REST settings save, the settings import and the WP-CLI write commands
 * all come through here, so a value means the same thing whichever way it
 * arrives. OptionSchema still clamps on the way into the database; this layer
 * is what tells the operator a value was wrong instead of quietly fixing it.
 */
final class OptionInput {

	/**
	 * Most entries a list setting may hold. Every request reads the whole
	 * option, so an unbounded list would slow the site down for good.
	 */
	public const MAX_LIST_ENTRIES = 5000;

	/**
	 * Keys with a dedicated list/text parser.
	 *
	 * @var array<string, class-string>
	 */
	private const PARSERS = [
		'ip_whitelist'      => IpListParser::class,
		'ip_blacklist'      => IpListParser::class,
		'trusted_proxies'   => IpListParser::class,
		'blocked_countries' => CountryListParser::class,
		'filter_params'     => FilterParamsParser::class,
		'blocked_bots'      => BotListParser::class,
		'admin_alert_email' => EmailListParser::class,
	];

	/**
	 * Parse a batch of submitted values.
	 *
	 * @param array<string|int, mixed> $raw    Submitted key => value pairs.
	 * @param array<int, string>       $locked Keys pinned by a constant; never written.
	 * @return InputReport
	 */
	public static function parse( array $raw, array $locked = [] ): InputReport {
		$defaults = Options::get_defaults();
		$values   = [];
		$errors   = [];
		$skipped  = [];
		$unknown  = [];

		foreach ( $raw as $key => $value ) {
			$key = (string) $key;

			if ( ! array_key_exists( $key, $defaults ) ) {
				$unknown[] = $key;
				continue;
			}

			if ( in_array( $key, $locked, true ) ) {
				$skipped[] = $key;
				continue;
			}

			$result = self::parse_value( $key, $value );

			if ( $result->is_valid() ) {
				$values[ $key ] = $result->value();
			} else {
				$errors[ $key ] = $result->errors();
			}
		}

		return new InputReport( $values, $errors, $skipped, $unknown );
	}

	/**
	 * Parse one value for a known key.
	 *
	 * @param string $key   Option key.
	 * @param mixed  $value Raw value.
	 * @return ParseResult
	 */
	public static function parse_value( string $key, mixed $value ): ParseResult {
		if ( isset( self::PARSERS[ $key ] ) ) {
			$entries = ListSplitter::split( $value );

			if ( null !== $entries && count( $entries ) > self::MAX_LIST_ENTRIES ) {
				/* translators: %d: maximum number of entries */
				return ParseResult::fail( [ sprintf( __( 'Too many entries: at most %d are allowed.', 'lw-firewall' ), self::MAX_LIST_ENTRIES ) ] );
			}

			return ( self::PARSERS[ $key ] )::parse( $value );
		}

		$ranges = OptionSchema::ranges();
		if ( isset( $ranges[ $key ] ) ) {
			return IntParser::parse( $value, $ranges[ $key ][0], $ranges[ $key ][1] );
		}

		$enums = OptionSchema::enums();
		if ( isset( $enums[ $key ] ) ) {
			return EnumParser::parse( $value, $enums[ $key ] );
		}

		if ( is_bool( Options::get_defaults()[ $key ] ?? null ) ) {
			return BoolParser::parse( $value );
		}

		/* translators: %s: setting key */
		return ParseResult::fail( [ sprintf( __( 'Unknown setting: %s.', 'lw-firewall' ), $key ) ] );
	}
}
