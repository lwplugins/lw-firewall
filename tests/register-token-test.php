<?php
/**
 * Dependency-free test for RegisterToken. Run: php tests/register-token-test.php
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

define( 'ABSPATH', __DIR__ . '/' );

if ( ! function_exists( 'wp_salt' ) ) {
	/**
	 * Stub WordPress wp_salt() with a fixed secret for deterministic HMACs.
	 *
	 * @param string $scheme Salt scheme (ignored).
	 * @return string
	 */
	function wp_salt( string $scheme = 'auth' ): string {
		return 'unit-test-fixed-salt-value';
	}
}

require __DIR__ . '/../includes/Storage/StorageInterface.php';
require __DIR__ . '/../includes/Rules/RegisterToken.php';

use LightweightPlugins\Firewall\Rules\RegisterToken;
use LightweightPlugins\Firewall\Storage\StorageInterface;

$failures = 0;

/**
 * Assert a condition and track failures.
 *
 * @param string $label Test label.
 * @param bool   $cond  Condition that must be true.
 * @return void
 */
function check_that( string $label, bool $cond ): void {
	global $failures;
	if ( $cond ) {
		echo "PASS: {$label}\n";
	} else {
		echo "FAIL: {$label}\n";
		++$failures;
	}
}

$storage = new class() implements StorageInterface {
	/** @var array<string, mixed> */
	private array $data = [];
	public function get( string $key ): mixed {
		return $this->data[ $key ] ?? null; }
	public function set( string $key, mixed $value, int $ttl ): bool {
		$this->data[ $key ] = $value;
		return true; }
	public function increment( string $key, int $ttl ): int {
		$this->data[ $key ] = (int) ( $this->data[ $key ] ?? 0 ) + 1;
		return $this->data[ $key ]; }
	public static function is_available(): bool {
		return true; }
};

$now = 1000000;
$min = 2;
$max = 3600;

$valid = RegisterToken::make( $now - 10 );
check_that( 'valid fresh token passes', true === RegisterToken::check( $valid, $now, $min, $max ) );

check_that( 'empty token rejected', false === RegisterToken::check( '', $now, $min, $max ) );

$tampered = base64_encode( ( $now - 10 ) . ':deadbeef' );
check_that( 'tampered hmac rejected', false === RegisterToken::check( $tampered, $now, $min, $max ) );

$expired = RegisterToken::make( $now - ( $max + 1 ) );
check_that( 'expired token rejected', false === RegisterToken::check( $expired, $now, $min, $max ) );

$fast = RegisterToken::make( $now );
check_that( 'too-fast token rejected', false === RegisterToken::check( $fast, $now, $min, $max ) );

$single = RegisterToken::make( $now - 10 );
check_that( 'single-use first pass', true === RegisterToken::check( $single, $now, $min, $max, $storage ) );
check_that( 'single-use replay rejected', false === RegisterToken::check( $single, $now, $min, $max, $storage ) );

echo 0 === $failures ? "\nALL PASSED\n" : "\n{$failures} FAILED\n";
exit( 0 === $failures ? 0 : 1 );
