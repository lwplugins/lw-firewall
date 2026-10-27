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
		public string $user_email = '';
		/** @var string[] */
		public array $roles = array();

		/**
		 * @param string[] $roles Roles on the current site.
		 */
		public function __construct( int $id = 0, string $login = '', string $display_name = '', array $roles = array() ) {
			$this->ID           = $id;
			$this->user_login   = $login;
			$this->display_name = $display_name;
			$this->roles        = $roles;
		}
	}
}
