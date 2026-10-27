<?php
/**
 * Minimal WP_Session_Tokens stand-in for unit tests (records destroyed tokens).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! class_exists( 'WP_Session_Tokens' ) ) {
	// phpcs:ignore
	class WP_Session_Tokens {

		/**
		 * Destroyed tokens per user.
		 *
		 * @var array<int, string[]>
		 */
		public static array $destroyed = array();

		private int $user_id;

		private function __construct( int $user_id ) {
			$this->user_id = $user_id;
		}

		public static function get_instance( $user_id ): self {
			return new self( (int) $user_id );
		}

		public function destroy( $token ): void {
			self::$destroyed[ $this->user_id ][] = (string) $token;
		}
	}
}
