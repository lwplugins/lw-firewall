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

		/**
		 * Codes added after the first one.
		 *
		 * @var array<int, string>
		 */
		private array $extra = array();

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

		public function add( string $code, string $message, mixed $data = '' ): void {
			if ( '' === $this->code ) {
				$this->code    = $code;
				$this->message = $message;
				$this->data    = $data;
				return;
			}

			$this->extra[] = $code;
		}

		public function has_errors(): bool {
			return '' !== $this->code;
		}

		/**
		 * @return array<int, string>
		 */
		public function get_error_codes(): array {
			return '' === $this->code ? array() : array_merge( array( $this->code ), $this->extra );
		}
	}
}
