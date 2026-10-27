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
		 * @param array<string, mixed> $params Request parameters.
		 */
		public function __construct( private array $params = array() ) {}

		public function get_param( string $key ): mixed {
			return $this->params[ $key ] ?? null;
		}
	}
}
