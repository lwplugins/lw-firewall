<?php
/**
 * A $wpdb stand-in backed by an in-memory SQLite usermeta table.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace {
	if ( ! class_exists( 'wpdb' ) ) {
		// phpcs:ignore
		class wpdb {
			public string $usermeta = 'wp_usermeta';

			public string $last_error = '';
		}
	}
}

namespace LightweightPlugins\Firewall\Tests\Unit\Support {

	/**
	 * Runs the real SQL of the counters (prepare() mimics %d / %s / %%).
	 * Set $fail to make every statement fail like a lost connection.
	 */
	final class FakeWpdb extends \wpdb {

		public bool $fail = false;

		public \PDO $pdo;

		public function __construct() {
			$this->usermeta = 'wp_usermeta';
			$this->pdo      = new \PDO( 'sqlite::memory:' );
			$this->pdo->setAttribute( \PDO::ATTR_ERRMODE, \PDO::ERRMODE_SILENT );
			$this->pdo->exec( 'CREATE TABLE wp_usermeta (umeta_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, meta_key TEXT, meta_value TEXT)' );
		}

		public function prepare( string $query, ...$args ): string {
			$i = 0;
			return (string) preg_replace_callback(
				'/%%|%d|%s/',
				function ( array $m ) use ( &$i, $args ): string {
					if ( '%%' === $m[0] ) {
						return '%';
					}
					$value = $args[ $i++ ];
					return '%d' === $m[0] ? (string) (int) $value : (string) $this->pdo->quote( (string) $value );
				},
				$query
			);
		}

		public function esc_like( string $text ): string {
			return addcslashes( $text, '_%\\' );
		}

		/**
		 * @return int|false
		 */
		public function query( string $sql ) {
			if ( $this->fail ) {
				$this->last_error = 'gone away';
				return false;
			}
			$this->last_error = '';
			$sql              = (string) preg_replace( "/LIKE ('(?:[^']|'')*')/", "LIKE $1 ESCAPE '\\\\'", $sql );
			$result           = $this->pdo->exec( $sql );
			if ( false === $result ) {
				$this->last_error = (string) $this->pdo->errorInfo()[2];
			}
			return $result;
		}

		/**
		 * @return mixed
		 */
		public function get_var( string $sql ) {
			if ( $this->fail ) {
				$this->last_error = 'gone away';
				return null;
			}
			$this->last_error = '';
			$statement        = $this->pdo->query( $sql );
			if ( false === $statement ) {
				$this->last_error = (string) $this->pdo->errorInfo()[2];
				return null;
			}
			$value = $statement->fetchColumn();
			return false === $value || null === $value ? null : (string) $value;
		}

		/**
		 * Raw rows for assertions.
		 *
		 * @return array<int, array<string, mixed>>
		 */
		public function rows(): array {
			return $this->pdo->query( 'SELECT user_id, meta_key, meta_value FROM wp_usermeta ORDER BY umeta_id' )->fetchAll( \PDO::FETCH_ASSOC );
		}
	}
}
