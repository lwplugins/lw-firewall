<?php
/**
 * Password-only logins waiting for their second factor.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\IpDetector;
use LightweightPlugins\Firewall\IpSubject;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The browser holds a random token; the store keeps only its SHA-256 as the
 * transient name, so a database read does not hand out usable tokens. A
 * record is bound to the client's IP subject (IPv6 by /64), lives five
 * minutes and allows five answers. Attempts are claimed before an answer is
 * checked, with an atomic database counter in the account's usermeta
 * (AttemptCounter, fail closed), so parallel requests cannot spend more than
 * five guesses on one token, whatever the firewall storage backend does.
 *
 * An enrollment record (forced enrollment, see EnrollmentController) lives
 * ten minutes and also carries the new TOTP secret (sealed with SecretBox),
 * the hashed e-mail code (EnrollmentMail) and, after a confirmed code, the
 * `enrolled` flag: the record then waits for the "continue" step.
 */
final class PendingLogin {

	/**
	 * Lifetime in seconds.
	 */
	public const TTL = 300;

	/**
	 * Lifetime of a forced-enrollment record (time to add the key to an app).
	 */
	public const ENROLL_TTL = 600;

	/**
	 * Window of the per-token attempt counters (covers both lifetimes).
	 */
	private const WINDOW = self::ENROLL_TTL;

	/**
	 * Wrong answers allowed per token.
	 */
	public const MAX_ATTEMPTS = 5;

	private const PREFIX = 'lwfw_2fa_';

	/**
	 * Usermeta key prefix of the per-token attempt counters.
	 */
	public const ATTEMPT_PREFIX = '_lw_firewall_2fa_tok_';

	/**
	 * Constructor.
	 *
	 * @param string|null         $ip      Client address (tests); null = IpDetector.
	 * @param \Closure|null       $clock   Returns the current Unix time (tests); null = time().
	 * @param AttemptCounter|null $counter Attempt counters; null = the database counter.
	 */
	public function __construct(
		private readonly ?string $ip = null,
		private readonly ?\Closure $clock = null,
		private readonly ?AttemptCounter $counter = null
	) {}

	/**
	 * Start a pending login.
	 *
	 * @param int    $user_id     User who passed the password check.
	 * @param bool   $remember    "Remember me" of the login form.
	 * @param string $redirect_to Validated redirect target ('' = default).
	 * @param bool   $secure      Whether the session cookie must be secure-only.
	 * @param string $enroll      Base32 TOTP secret of a forced enrollment ('' = a challenge).
	 * @return string 32 char hex token.
	 */
	public function create( int $user_id, bool $remember, string $redirect_to, bool $secure = false, string $enroll = '' ): string {
		$token = bin2hex( random_bytes( 16 ) );

		// Fresh counter for this token; drop the account's expired ones.
		$this->counter()->purge( $user_id, self::ATTEMPT_PREFIX, self::WINDOW );
		$this->counter()->hold( $user_id, self::attempt_key( $token ), 0 );

		$this->save(
			$token,
			array(
				'user_id'     => $user_id,
				'remember'    => $remember,
				'redirect_to' => $redirect_to,
				'ip_key'      => $this->ip_key(),
				'secure'      => $secure,
				'expires'     => $this->now() + ( '' === $enroll ? self::TTL : self::ENROLL_TTL ),
				'passkey_key' => '',
				'enroll'      => '' === $enroll ? '' : SecretBox::seal( $enroll ),
				'enrolled'    => false,
				'mail'        => array(
					'hash'    => '',
					'expires' => 0,
					'failed'  => false,
				),
			)
		);

		return $token;
	}

	/**
	 * The record of a token, when it exists, is unexpired and belongs to this IP.
	 *
	 * @param string $token Token from create().
	 * @return array{user_id: int, remember: bool, redirect_to: string, ip_key: string, secure: bool, expires: int, passkey_key: string, enroll: string, enrolled: bool, mail: array{hash: string, expires: int, failed: bool}}|null
	 */
	public function get( string $token ): ?array {
		if ( 1 !== preg_match( '/^[0-9a-f]{32}$/D', $token ) ) {
			return null;
		}

		$record = get_transient( self::name( $token ) );
		if ( ! is_array( $record ) || ! self::well_formed( $record ) ) {
			return null;
		}
		if ( ! hash_equals( $record['ip_key'], $this->ip_key() ) || $record['expires'] <= $this->now() ) {
			return null;
		}

		return $record;
	}

	/**
	 * Claim one attempt, atomically, before the answer is checked.
	 *
	 * @param string $token Token.
	 * @return bool False when the token is unknown or its attempts are used up
	 *              (the token is then deleted).
	 */
	public function begin_attempt( string $token ): bool {
		$record = $this->get( $token );
		if ( null === $record ) {
			return false;
		}

		$count = $this->counter()->increment( $record['user_id'], self::attempt_key( $token ), self::WINDOW );
		if ( $count > self::MAX_ATTEMPTS ) {
			$this->drop( $token, $record['user_id'] );
			return false;
		}

		return true;
	}

	/**
	 * Attempts claimed so far.
	 *
	 * @param string $token Token.
	 */
	public function attempts( string $token ): int {
		$record = $this->get( $token );

		return null === $record ? 0 : $this->counter()->count( $record['user_id'], self::attempt_key( $token ), self::WINDOW );
	}

	/**
	 * After a wrong answer: how many are left (the token is deleted at 0).
	 *
	 * @param string $token Token.
	 * @return int Answers left; 0 = the token is gone.
	 */
	public function fail( string $token ): int {
		$record = $this->get( $token );
		if ( null === $record ) {
			return 0;
		}

		$used = $this->counter()->count( $record['user_id'], self::attempt_key( $token ), self::WINDOW );
		$left = $used >= self::MAX_ATTEMPTS ? 0 : self::MAX_ATTEMPTS - $used;
		if ( 0 === $left ) {
			$this->drop( $token, $record['user_id'] );
			return 0;
		}

		return $left;
	}

	/**
	 * Remember the passkey challenge issued for this login (server side only).
	 *
	 * @param string $token Token.
	 * @param string $key   ChallengeStore key.
	 */
	public function attach_passkey( string $token, string $key ): bool {
		return $this->patch( $token, array( 'passkey_key' => $key ) );
	}

	/**
	 * Overwrite fields of a live record (unknown keys and a broken shape are refused).
	 *
	 * @param string               $token  Token.
	 * @param array<string, mixed> $fields Fields to replace.
	 * @param int                  $ttl    New lifetime from now; 0 = keep the expiry (a write never extends it).
	 */
	public function patch( string $token, array $fields, int $ttl = 0 ): bool {
		$record = $this->get( $token );
		if ( null === $record || array() !== array_diff_key( $fields, $record ) ) {
			return false;
		}

		$record = array_replace( $record, $fields );
		if ( $ttl > 0 ) {
			$record['expires'] = $this->now() + $ttl;
		}
		if ( ! self::well_formed( $record ) ) {
			return false;
		}
		$this->save( $token, $record );

		return true;
	}

	/**
	 * The plain TOTP secret of an enrollment record (null = not one, or unreadable).
	 *
	 * @param array<string, mixed> $record Record from get().
	 */
	public static function enroll_secret( array $record ): ?string {
		$sealed = $record['enroll'] ?? '';

		return is_string( $sealed ) && '' !== $sealed ? SecretBox::open( $sealed ) : null;
	}

	/**
	 * Fetch and delete (single use). Only the request whose delete removed the
	 * row gets the record, so two parallel correct answers yield one session.
	 *
	 * @param string $token Token.
	 * @return array{user_id: int, remember: bool, redirect_to: string, ip_key: string, secure: bool, expires: int, passkey_key: string, enroll: string, enrolled: bool, mail: array{hash: string, expires: int, failed: bool}}|null
	 */
	public function consume( string $token ): ?array {
		$record = $this->get( $token );
		if ( null === $record || ! delete_transient( self::name( $token ) ) ) {
			return null;
		}

		$this->counter()->delete( $record['user_id'], self::attempt_key( $token ) );

		return $record;
	}

	/**
	 * Write a record with its remaining lifetime (a write never extends it).
	 *
	 * @param string               $token  Token.
	 * @param array<string, mixed> $record Record.
	 */
	private function save( string $token, array $record ): void {
		set_transient( self::name( $token ), $record, max( 1, (int) $record['expires'] - $this->now() ) );
	}

	/**
	 * Whether a stored value has the record shape.
	 *
	 * @param array<mixed> $record Stored value.
	 */
	private static function well_formed( array $record ): bool {
		return is_int( $record['user_id'] ?? null ) && $record['user_id'] > 0
			&& is_bool( $record['remember'] ?? null )
			&& is_string( $record['redirect_to'] ?? null )
			&& is_string( $record['ip_key'] ?? null )
			&& is_bool( $record['secure'] ?? null )
			&& is_int( $record['expires'] ?? null )
			&& is_string( $record['passkey_key'] ?? null )
			&& is_string( $record['enroll'] ?? null )
			&& is_bool( $record['enrolled'] ?? null )
			&& is_string( $record['mail']['hash'] ?? null )
			&& is_int( $record['mail']['expires'] ?? null )
			&& is_bool( $record['mail']['failed'] ?? null );
	}

	/**
	 * Transient name of a token.
	 *
	 * @param string $token Token.
	 */
	private static function name( string $token ): string {
		return self::PREFIX . hash( 'sha256', $token );
	}

	/**
	 * Delete a token and its counter.
	 *
	 * @param string $token   Token.
	 * @param int    $user_id Account.
	 */
	private function drop( string $token, int $user_id ): void {
		delete_transient( self::name( $token ) );
		$this->counter()->delete( $user_id, self::attempt_key( $token ) );
	}

	/**
	 * Usermeta key of a token's attempt counter (16 hex of its SHA-256).
	 *
	 * @param string $token Token.
	 */
	private static function attempt_key( string $token ): string {
		return self::ATTEMPT_PREFIX . substr( hash( 'sha256', $token ), 0, 16 );
	}

	/**
	 * Attempt counter (shared with the enrollment binding claim).
	 */
	public function counter(): AttemptCounter {
		return $this->counter ?? new AttemptCounter( $this->clock );
	}

	/**
	 * The client's IP subject.
	 */
	private function ip_key(): string {
		return IpSubject::of( $this->ip ?? IpDetector::get_ip() );
	}

	/**
	 * Current Unix time (the store's clock).
	 */
	public function now(): int {
		return null === $this->clock ? time() : (int) ( $this->clock )();
	}
}
