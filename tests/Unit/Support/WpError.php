<?php
/**
 * Minimal WP_Error double for unit tests (WordPress is not loaded).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! class_exists( 'WP_Error' ) ) {
	// phpcs:ignore
	class WP_Error {
		public string $code;
		public string $message;

		public function __construct( string $code = '', string $message = '' ) {
			$this->code    = $code;
			$this->message = $message;
		}

		public function get_error_code(): string {
			return $this->code;
		}
	}
}
