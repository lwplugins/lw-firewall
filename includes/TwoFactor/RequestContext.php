<?php
/**
 * What kind of request a login happens in.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Only an interactive login (wp-login.php, a front-end login form) can be
 * sent to the second-factor page. Every other context where a password can
 * reach the `authenticate` filter has no page to show, so PasswordAuthGuard
 * refuses a password-only sign-in there instead — except WP-CLI, whose
 * operator already has shell access.
 */
final class RequestContext {

	private const NON_INTERACTIVE = array( 'ajax', 'cron', 'cli', 'xmlrpc', 'rest' );

	/**
	 * Constructor.
	 *
	 * @param array<string, bool>|null $flags Fixed flags (tests); null = detect.
	 */
	public function __construct( private readonly ?array $flags = null ) {}

	/**
	 * Whether a login here may be redirected to the challenge page.
	 */
	public function is_interactive(): bool {
		foreach ( self::NON_INTERACTIVE as $flag ) {
			if ( $this->is( $flag ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Whether a password alone must be refused for a two-factor user here.
	 */
	public function refuses_passwords(): bool {
		return ! $this->is_interactive() && ! $this->is( 'cli' );
	}

	/**
	 * One flag: ajax, cron, cli, xmlrpc or rest.
	 *
	 * @param string $flag Flag name.
	 */
	public function is( string $flag ): bool {
		if ( null !== $this->flags ) {
			return ! empty( $this->flags[ $flag ] );
		}

		return match ( $flag ) {
			'ajax'   => wp_doing_ajax(),
			'cron'   => wp_doing_cron(),
			'cli'    => defined( 'WP_CLI' ) && WP_CLI,
			'xmlrpc' => defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST,
			'rest'   => defined( 'REST_REQUEST' ) && REST_REQUEST,
			default  => false,
		};
	}
}
