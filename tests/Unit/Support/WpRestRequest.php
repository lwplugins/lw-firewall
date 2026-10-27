<?php
/**
 * Minimal WP_REST_Request double for unit tests (WordPress is not loaded).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! class_exists( 'WP_REST_Request' ) ) {
	// phpcs:ignore
	class WP_REST_Request {
		/**
		 * @var array<string, string>
		 */
		private array $headers = array();

		/**
		 * @param array<string, mixed>  $params  Request parameters.
		 * @param array<string, string> $headers Headers (default: a JSON body).
		 */
		public function __construct( private array $params = array(), array $headers = array( 'content-type' => 'application/json' ) ) {
			foreach ( $headers as $name => $value ) {
				$this->headers[ strtolower( $name ) ] = $value;
			}
		}

		public function get_param( string $key ): mixed {
			return $this->params[ $key ] ?? null;
		}

		public function get_header( string $key ): ?string {
			return $this->headers[ strtolower( $key ) ] ?? null;
		}

		public function is_json_content_type(): bool {
			$type = $this->headers['content-type'] ?? '';

			return str_contains( strtolower( $type ), 'json' );
		}
	}
}
