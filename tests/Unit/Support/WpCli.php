<?php
/**
 * Minimal WP_CLI double for unit tests (WP-CLI is not loaded).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! class_exists( 'WP_CLI' ) ) {
	// phpcs:ignore
	class WP_CLI {
		/**
		 * @var string[]
		 */
		public static array $log = array();

		/**
		 * @var string[]
		 */
		public static array $successes = array();

		/**
		 * @var string[]
		 */
		public static array $confirmed = array();

		public static function reset(): void {
			self::$log       = array();
			self::$successes = array();
			self::$confirmed = array();
		}

		public static function log( string $message ): void {
			self::$log[] = $message;
		}

		public static function success( string $message ): void {
			self::$successes[] = $message;
		}

		public static function error( string $message ): void {
			throw new \RuntimeException( $message ); // phpcs:ignore WordPress.Security.EscapeOutput
		}

		/**
		 * @param array<string, mixed> $assoc_args Associative arguments.
		 */
		public static function confirm( string $question, array $assoc_args = array() ): void {
			if ( empty( $assoc_args['yes'] ) ) {
				throw new \RuntimeException( 'confirm: ' . $question ); // phpcs:ignore WordPress.Security.EscapeOutput
			}
			self::$confirmed[] = $question;
		}
	}
}
