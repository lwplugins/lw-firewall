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
		public mixed $data;

		public function __construct( string $code = '', string $message = '', mixed $data = '' ) {
			$this->code    = $code;
			$this->message = $message;
			$this->data    = $data;
		}

		public function get_error_data(): mixed {
			return $this->data;
		}

		public function get_error_code(): string {
			return $this->code;
		}
	}
}
