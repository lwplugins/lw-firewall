<?php
/**
 * Minimal WP_User double for unit tests (WordPress is not loaded).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! class_exists( 'WP_User' ) ) {
	// phpcs:ignore
	class WP_User {
		public int $ID;
		public string $user_login;
		public string $display_name;

		public function __construct( int $id = 0, string $login = '', string $display_name = '' ) {
			$this->ID           = $id;
			$this->user_login   = $login;
			$this->display_name = $display_name;
		}
	}
}
