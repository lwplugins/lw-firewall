<?php
/**
 * Genuine-Googlebot verification (reverse + forward DNS).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Storage\StorageInterface;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Confirms that a client claiming to be Googlebot really is one.
 *
 * Google's documented method: the address must reverse-resolve to a host under
 * googlebot.com or google.com, and that host must resolve back to the same
 * address. The User-Agent alone proves nothing, so it only decides whether the
 * (slow) DNS check runs at all. Results are cached for a day per address.
 */
final class GooglebotVerifier {

	/**
	 * Verdict cache lifetime in seconds.
	 */
	private const TTL = 86400;

	/**
	 * Accepted reverse-DNS domains.
	 *
	 * @var array<int, string>
	 */
	private const DOMAINS = [ '.googlebot.com', '.google.com' ];

	/**
	 * Reverse lookup: address → hostname (or '' when none).
	 *
	 * @var callable(string): string
	 */
	private $reverse;

	/**
	 * Forward lookup: hostname → list of addresses.
	 *
	 * @var callable(string): array<int, string>
	 */
	private $forward;

	/**
	 * Constructor.
	 *
	 * @param StorageInterface                            $storage Verdict cache.
	 * @param (callable(string): string)|null             $reverse Reverse lookup (test seam).
	 * @param (callable(string): array<int, string>)|null $forward Forward lookup (test seam).
	 */
	public function __construct( private StorageInterface $storage, ?callable $reverse = null, ?callable $forward = null ) {
		$this->reverse = $reverse ?? static fn ( string $ip ): string => self::reverse_lookup( $ip );
		$this->forward = $forward ?? static fn ( string $host ): array => self::forward_lookup( $host );
	}

	/**
	 * Whether the client is a verified Googlebot.
	 *
	 * @param string $ip         Client IP.
	 * @param string $user_agent Client User-Agent.
	 * @return bool
	 */
	public function is_verified( string $ip, string $user_agent ): bool {
		if ( false === stripos( $user_agent, 'googlebot' ) || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$key    = 'gbot_' . md5( $ip );
		$cached = $this->storage->get( $key );

		if ( null !== $cached && false !== $cached ) {
			return 1 === (int) $cached;
		}

		$verified = $this->resolve( $ip );
		$this->storage->set( $key, $verified ? 1 : 0, self::TTL );

		return $verified;
	}

	/**
	 * Whether a hostname belongs to Googlebot.
	 *
	 * @param string $host Reverse-DNS hostname.
	 * @return bool
	 */
	public static function is_google_host( string $host ): bool {
		$host = strtolower( rtrim( $host, '.' ) );

		foreach ( self::DOMAINS as $domain ) {
			if ( str_ends_with( $host, $domain ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Run the reverse + forward check.
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	private function resolve( string $ip ): bool {
		$host = (string) ( $this->reverse )( $ip );

		if ( '' === $host || ! self::is_google_host( $host ) ) {
			return false;
		}

		$packed = inet_pton( $ip );

		foreach ( ( $this->forward )( $host ) as $address ) {
			if ( false !== $packed && @inet_pton( $address ) === $packed ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- DNS may return junk.
				return true;
			}
		}

		return false;
	}

	/**
	 * System reverse lookup.
	 *
	 * @param string $ip Address.
	 * @return string
	 */
	private static function reverse_lookup( string $ip ): string {
		$host = gethostbyaddr( $ip );

		return ( false === $host || $host === $ip ) ? '' : $host;
	}

	/**
	 * System forward lookup (A and AAAA).
	 *
	 * @param string $host Hostname.
	 * @return array<int, string>
	 */
	private static function forward_lookup( string $host ): array {
		$records = dns_get_record( $host, DNS_A | DNS_AAAA );
		$list    = [];

		foreach ( is_array( $records ) ? $records : [] as $record ) {
			$list[] = (string) ( $record['ip'] ?? $record['ipv6'] ?? '' );
		}

		return $list;
	}
}
