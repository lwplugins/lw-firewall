<?php
/**
 * Tests for forced two-factor enrollment at login.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\TwoFactor\RememberDevice;
use LightweightPlugins\Firewall\TwoFactor\Totp;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\EnrollmentController
 * @covers \LightweightPlugins\Firewall\TwoFactor\EnrollmentPage
 * @covers \LightweightPlugins\Firewall\TwoFactor\ChallengeController
 * @covers \LightweightPlugins\Firewall\TwoFactor\LoginInterceptor
 * @covers \LightweightPlugins\Firewall\TwoFactor\PendingLogin
 */
final class EnrollmentFlowTest extends MonkeyTestCase {

	use LoginFlowTrait {
		setUp as flow_set_up;
	}

	private const SECRET = 'JBSWY3DPEHPK3PXP';

	protected function setUp(): void {
		$this->flow_set_up();
		if ( ! defined( 'DAY_IN_SECONDS' ) ) {
			define( 'DAY_IN_SECONDS', 86400 );
		}
		Functions\when( 'is_multisite' )->justReturn( false );
		Functions\when( 'wp_hash_password' )->alias( static fn ( $p ) => password_hash( (string) $p, PASSWORD_BCRYPT, array( 'cost' => 4 ) ) );
		$this->users[6]->roles = array( 'editor' );
		$this->enforce( 0 );
	}

	private function enforce( int $grace, int $remember_days = 0 ): void {
		OptionStore::install(
			array(
				'lw_firewall' => array(
					'log_enabled'          => false,
					'twofa_enabled'        => true,
					'twofa_required_roles' => array( 'editor' ),
					'twofa_grace_days'     => $grace,
					'twofa_remember_days'  => $remember_days,
				),
			)
		);
	}

	/**
	 * The secret shown on the enrollment screen (from the otpauth link).
	 */
	private function secret_in( string $html ): string {
		$this->assertSame( 1, preg_match( '/otpauth:\/\/totp\/[^"]*[?&]secret=([A-Z2-7]+)/', $html, $m ), 'The screen carries an otpauth link.' );
		return $m[1];
	}

	private function code_for( string $secret ): string {
		return Totp::code_at( $secret, intdiv( $this->now, 30 ) );
	}

	/**
	 * @return string[] Recovery codes printed on a screen.
	 */
	private function codes_in( string $html ): array {
		preg_match_all( '/\b[2-9a-z]{4}-[2-9a-z]{4}\b/', $html, $m );
		return array_values( array_unique( $m[0] ) );
	}

	public function test_inside_the_grace_period_the_login_is_not_held(): void {
		$this->enforce( 7 );

		$this->interceptor()->on_wp_login( 'bob', $this->users[6] );

		$this->assertSame( 0, $this->cleared );
		$this->assertSame( array(), $this->redirects );
	}

	public function test_after_the_grace_period_the_login_goes_to_enrollment_without_a_session(): void {
		$interceptor = $this->interceptor();
		$this->signon->start( 'bob', 'pw' );
		$this->assertFalse( $interceptor->filter_send_cookies( true, 0, 0, 6, 'secure_auth', 'tok-bob' ), 'The session cookie is withheld.' );

		$token = $this->login( 6, $interceptor );

		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/D', $token );
		$this->assertSame( 1, $this->cleared );
		$this->assertSame( array( 6 => array( 'tok-bob' ) ), \WP_Session_Tokens::$destroyed );
		$this->assertSame( array(), $this->cookies );
	}

	public function test_the_enrollment_screen_shows_the_key_and_link_but_never_as_a_hidden_field(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 6, $interceptor );

		$html   = $this->open( $interceptor, $token );
		$secret = $this->secret_in( $html );

		$this->assertSame( 32, strlen( $secret ) );
		$this->assertStringContainsString( implode( ' ', str_split( $secret, 4 ) ), $html, 'The key is grouped in blocks of four.' );
		$this->assertStringContainsString( 'issuer=Example%20%26%20Co', $html );
		preg_match_all( '/<input[^>]*>/i', $html, $inputs );
		foreach ( $inputs[0] as $input ) {
			$this->assertStringNotContainsString( $secret, $input );
		}
		$this->assertStringNotContainsString( $secret, (string) end( $this->redirects ) );
		$this->assertSame( $secret, $this->secret_in( $this->open( $interceptor, $token ) ), 'Reloading keeps the same key.' );
	}

	public function test_the_pending_secret_is_stored_sealed(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 6, $interceptor );
		$secret      = $this->secret_in( $this->open( $interceptor, $token ) );

		$this->assertStringNotContainsString( $secret, serialize( $this->transients ) );
	}

	public function test_a_right_code_enrolls_and_shows_the_recovery_codes_once(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 6, $interceptor );
		$secret      = $this->secret_in( $this->open( $interceptor, $token ) );

		Actions\expectDone( 'lw_firewall_2fa_enrolled' )->once()->with( 6, 'totp' );
		$html = $this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code_for( $secret ) ) );

		$factors = new UserFactors( 6 );
		$this->assertSame( $secret, $factors->totp_secret() );
		$this->assertSame( intdiv( $this->now, 30 ), $factors->totp_last_step(), 'The confirming code cannot be replayed.' );
		$this->assertCount( 10, $factors->recovery_hashes() );
		$codes = $this->codes_in( $html );
		$this->assertCount( 10, $codes );
		$this->assertSame( array(), $this->cookies, 'No session before the codes are acknowledged.' );
		$this->assertStringContainsString( 'name="lwfw_step" value="continue"', $html );
		$this->assertStringNotContainsString( $codes[0], serialize( $this->transients ), 'Plain codes are not kept server side.' );

		$again = $this->open( $interceptor, $token );
		$this->assertSame( array(), $this->codes_in( $again ), 'A second visit does not show the codes.' );
		$this->assertStringContainsString( 'name="lwfw_step" value="continue"', $again );
	}

	public function test_continue_starts_the_session_once(): void {
		$_POST['rememberme'] = '1';
		$interceptor         = $this->interceptor();
		$token               = $this->login( 6, $interceptor );
		$secret              = $this->secret_in( $this->open( $interceptor, $token ) );
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code_for( $secret ) ) );

		Actions\expectDone( 'lw_firewall_2fa_passed' )->once()->with( 6, 'totp' );
		$this->submit( $interceptor, $token, array( 'lwfw_step' => 'continue' ) );

		$this->assertSame( array( array( 6, true ) ), $this->cookies );
		$this->assertSame( 'https://example.com/wp-admin/', end( $this->redirects ) );
		$this->assertNull( $this->store()->get( $token ) );

		$this->submit( $interceptor, $token, array( 'lwfw_step' => 'continue' ) );
		$this->assertCount( 1, $this->cookies, 'Single use.' );
	}

	public function test_continue_needs_the_nonce(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 6, $interceptor );
		$secret      = $this->secret_in( $this->open( $interceptor, $token ) );
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code_for( $secret ) ) );

		$this->submit( $interceptor, $token, array( 'lwfw_step' => 'continue', 'lwfw_2fa_nonce' => 'forged' ) );

		$this->assertSame( array(), $this->cookies );
		$this->assertNotNull( $this->store()->get( $token ) );
	}

	public function test_a_resubmitted_confirmation_does_not_finish_or_show_codes(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 6, $interceptor );
		$secret      = $this->secret_in( $this->open( $interceptor, $token ) );
		$fields      = array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code_for( $secret ) );
		$this->submit( $interceptor, $token, $fields );
		$hashes = ( new UserFactors( 6 ) )->recovery_hashes();

		$html = $this->submit( $interceptor, $token, $fields );

		$this->assertSame( array(), $this->cookies );
		$this->assertSame( array(), $this->codes_in( $html ) );
		$this->assertSame( $hashes, ( new UserFactors( 6 ) )->recovery_hashes(), 'No second set of codes.' );
	}

	public function test_a_wrong_code_is_counted_like_a_failed_answer(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 6, $interceptor );
		$secret      = $this->secret_in( $this->open( $interceptor, $token ) );
		$wrong       = '000000' === $this->code_for( $secret ) ? '111111' : '000000';

		Actions\expectDone( 'wp_login_failed' )->once();
		$html = $this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $wrong ) );

		$this->assertFalse( ( new UserFactors( 6 ) )->has_any() );
		$this->assertSame( 1, $this->store()->attempts( $token ) );
		$this->assertSame( 1, $this->storage->count( 6, \LightweightPlugins\Firewall\TwoFactor\FailureThrottle::META_KEY, 900 ) );
		$this->assertSame( $secret, $this->secret_in( $html ), 'The same key is offered again.' );
	}

	public function test_five_wrong_codes_end_the_enrollment(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 6, $interceptor );
		$secret      = $this->secret_in( $this->open( $interceptor, $token ) );

		for ( $i = 0; $i < 5; $i++ ) {
			$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => 'abc' ) );
		}
		$this->submit( $interceptor, $token, array( 'lwfw_method' => 'totp', 'lwfw_code' => $this->code_for( $secret ) ) );

		$this->assertNull( $this->store()->get( $token ) );
		$this->assertFalse( ( new UserFactors( 6 ) )->has_any() );
	}

	public function test_a_remembered_device_does_not_skip_enrollment(): void {
		$this->enforce( 0, 14 );
		$sink     = array();
		$remember = new RememberDevice(
			fn (): int => $this->now,
			static function ( string $name, string $value ) use ( &$sink ): void {
				$sink[ $name ] = $value;
			}
		);
		$remember->issue( 6, 14 );
		$_COOKIE = $sink;
		$this->assertTrue( $remember->is_valid( 6 ) );

		$interceptor = $this->interceptor( array(), $remember );

		$this->assertTrue( $interceptor->intercepts( $this->users[6] ) );
		$_COOKIE = array();
	}

	public function test_a_user_who_enrolled_meanwhile_gets_start_over(): void {
		$interceptor = $this->interceptor();
		$token       = $this->login( 6, $interceptor );
		( new UserFactors( 6 ) )->save_totp( self::SECRET );

		$html = $this->open( $interceptor, $token );

		$this->assertStringNotContainsString( 'otpauth://', $html );
		$this->assertStringContainsString( 'https://example.com/wp-login.php', $html );
		$this->assertSame( self::SECRET, ( new UserFactors( 6 ) )->totp_secret(), 'An existing factor is never overwritten.' );
	}

	public function test_a_user_with_factors_still_gets_the_normal_challenge(): void {
		$this->users[5]->roles = array( 'editor' );
		$interceptor           = $this->interceptor();
		$token                 = $this->login( 5, $interceptor );

		$html = $this->open( $interceptor, $token );

		$this->assertStringNotContainsString( 'otpauth://', $html );
		$this->assertStringContainsString( 'one-time-code', $html );
	}
}
