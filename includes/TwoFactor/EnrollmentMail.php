<?php
/**
 * The e-mail code a forced enrollment must confirm before a factor binds.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Why: forced enrollment runs after a password-only login. Without a second
 * proof, whoever stole the password could bind their own authenticator and
 * keep the account even after the owner resets the password. The code goes
 * to the account's e-mail address, so binding needs the password AND the
 * mailbox.
 *
 * One six-digit code (random_int) per pending record, sent on the first view
 * of the setup screen, stored only as an HMAC (wp_salt + token) in the
 * record, valid ten minutes and spent together with the record. Wrong codes
 * count through ChallengeController's per-token and per-account claims.
 *
 * Trade-off when wp_mail() fails (or the account has no address): the step
 * is skipped rather than locking the user out; the failure is logged
 * (`twofa_enroll_mail_failed`) and administrators see MailFailureNotice
 * until they dismiss it or a later mail succeeds.
 */
final class EnrollmentMail {

	/**
	 * Validity of a code in seconds.
	 */
	public const VALIDITY = 600;

	/**
	 * Option flag (Unix time of the last failure) behind MailFailureNotice.
	 */
	public const FAILED_OPTION = 'lw_firewall_2fa_mail_failed';

	/**
	 * Constructor.
	 *
	 * @param PendingLogin $pending Pending-login store (and clock).
	 */
	public function __construct( private readonly PendingLogin $pending ) {}

	/**
	 * Send the code once per record; returns the record as now stored.
	 *
	 * @param string               $token  Pending token.
	 * @param WP_User              $user   Pending user.
	 * @param array<string, mixed> $record Record.
	 * @return array<string, mixed>
	 */
	public function ensure_sent( string $token, WP_User $user, array $record ): array {
		$mail = $record['mail'];
		if ( '' !== $mail['hash'] || $mail['failed'] ) {
			return $record;
		}

		$code  = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
		$email = is_string( $user->user_email ?? null ) ? $user->user_email : '';
		$sent  = '' !== $email && (bool) wp_mail( $email, $this->subject(), $this->body( $code ) );

		if ( $sent ) {
			delete_option( self::FAILED_OPTION );
			$mail = array(
				'hash'    => self::hash( $token, $code ),
				'expires' => $this->pending->now() + self::VALIDITY,
				'failed'  => false,
			);
		} else {
			FailureLog::record( FailureLog::ENROLL_MAIL_FAILED );
			update_option( self::FAILED_OPTION, $this->pending->now(), false );
			$mail = array(
				'hash'    => '',
				'expires' => 0,
				'failed'  => true,
			);
		}

		$this->pending->patch( $token, array( 'mail' => $mail ) );
		$record['mail'] = $mail;

		return $record;
	}

	/**
	 * Whether the record asks for the e-mail code (false after a mail failure).
	 *
	 * @param array<string, mixed> $record Record.
	 */
	public static function required( array $record ): bool {
		return empty( $record['mail']['failed'] );
	}

	/**
	 * Whether the submitted e-mail code is right (always true after a mail failure).
	 *
	 * @param string               $token  Pending token.
	 * @param array<string, mixed> $record Record.
	 * @param string               $code   Submitted code.
	 */
	public function accepts( string $token, array $record, string $code ): bool {
		if ( ! self::required( $record ) ) {
			return true;
		}

		$mail = $record['mail'];
		$code = (string) preg_replace( '/\s+/', '', $code );
		if ( '' === $mail['hash'] || $mail['expires'] <= $this->pending->now() || 1 !== preg_match( '/^[0-9]{6}$/D', $code ) ) {
			return false;
		}

		return hash_equals( $mail['hash'], self::hash( $token, $code ) );
	}

	/**
	 * The address shown on the screen, masked (j***@example.com).
	 *
	 * @param WP_User $user User.
	 */
	public static function masked( WP_User $user ): string {
		$email = is_string( $user->user_email ?? null ) ? $user->user_email : '';
		$at    = strrpos( $email, '@' );
		if ( false === $at || 0 === $at ) {
			return '';
		}

		return substr( $email, 0, 1 ) . '***' . substr( $email, $at );
	}

	/**
	 * HMAC of a code, bound to its token.
	 *
	 * @param string $token Pending token.
	 * @param string $code  Six digits.
	 */
	private static function hash( string $token, string $code ): string {
		return hash_hmac( 'sha256', $token . '|' . $code, wp_salt( 'auth' ) );
	}

	/**
	 * Mail subject.
	 */
	private function subject(): string {
		/* translators: %s: site name */
		return sprintf( __( '[%s] Your code to set up two-factor sign-in', 'lw-firewall' ), self::site() );
	}

	/**
	 * Mail body (plain text).
	 *
	 * @param string $code Six digits.
	 */
	private function body( string $code ): string {
		return implode(
			"\n",
			array(
				/* translators: %s: site name */
				sprintf( __( 'Someone signed in to your account at %s and is setting up two-factor sign-in.', 'lw-firewall' ), self::site() ),
				'',
				/* translators: %s: six-digit code */
				sprintf( __( 'Your code: %s', 'lw-firewall' ), $code ),
				__( 'It is valid for 10 minutes.', 'lw-firewall' ),
				'',
				__( 'If this was not you, do not share the code: change your password and contact an administrator of the site.', 'lw-firewall' ),
			)
		);
	}

	/**
	 * Site name, decoded.
	 */
	private static function site(): string {
		return wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
	}
}
