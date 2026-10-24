<?php
/**
 * Minimal WP_REST_Server double for unit tests (WordPress is not loaded).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! class_exists( 'WP_REST_Server' ) ) {
	// phpcs:ignore
	class WP_REST_Server {
		const READABLE  = 'GET';
		const CREATABLE = 'POST';
		const EDITABLE  = 'POST, PUT, PATCH';
		const DELETABLE = 'DELETE';
	}
}
