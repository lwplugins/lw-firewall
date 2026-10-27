<?php
/**
 * Tests for the factor-change notification and the mail-failure notice.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\TwoFactor;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use LightweightPlugins\Firewall\Tests\Unit\MonkeyTestCase;
use LightweightPlugins\Firewall\Tests\Unit\Support\OptionStore;
use LightweightPlugins\Firewall\TwoFactor\EnrollmentMail;
use LightweightPlugins\Firewall\TwoFactor\FactorNotifier;
use LightweightPlugins\Firewall\TwoFactor\MailFailureNotice;
use LightweightPlugins\Firewall\TwoFactor\PasskeyRecord;
use LightweightPlugins\Firewall\TwoFactor\UserFactors;

require_once dirname( __DIR__ ) . '/Support/WpUser.php';

/**
 * @covers \LightweightPlugins\Firewall\TwoFactor\FactorNotifier
 * @covers \LightweightPlugins\Firewall\TwoFactor\MailFailureNotice
 * @covers \LightweightPlugins\Firewall\TwoFactor\UserFactors
 */
final class FactorNotifierTest extends MonkeyTestCase {

	use UserMetaStubTrait;

	private const SECRET = 'JBSWY3DPEHPK3PXP';

	/**
	 * Captured mails.
	 *
	 * @var array<int, array{0: string, 1: string, 2: string}>
	 */
	private array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		$this->stub_user_meta();
		Functions\stubTranslationFunctions();
		Functions\stubEscapeFunctions();
		Functions\when( 'wp_salt' )->justReturn( 'salt' );
		Functions\when( 'wp_strip_all_tags' )->alias( static fn ( $s ) => strip_tags( (string) $s ) );
		Functions\when( 'get_bloginfo' )->justReturn( 'Example &amp; Co' );
		Functions\when( 'wp_specialchars_decode' )->alias( static fn ( $s ) => htmlspecialchars_decode( (string) $s, ENT_QUOTES ) );
		Functions\when( 'admin_url' )->alias( static fn ( $p = '' ) => 'https://example.com/wp-admin/' . $p );
		Functions\when( 'wp_nonce_url' )->alias( static fn ( $url, $action ) => $url . '&_wpnonce=n-' . $action );
		OptionStore::install( array( 'lw_firewall' => array( 'log_enabled' => false ) ) );
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2:3:4:5:6';
		$user                   = new \WP_User( 6, 'bob', 'Bob' );
		$user->user_email       = 'bob@example.com';
		Functions\when( 'get_userdata' )->alias( static fn ( $id ) => 6 === (int) $id ? $user : false );
		$this->mails = array();
		Functions\when( 'wp_mail' )->alias(
			function ( $to, $subject, $body ) {
				$this->mails[] = array( (string) $to, (string) $subject, (string) $body );
				return true;
			}
		);
	}

	protected function tearDown(): void {
		unset( $_SERVER['REMOTE_ADDR'] );
		parent::tearDown();
	}

	public function test_every_add_and_remove_fires_the_change_action(): void {
		$factors = new UserFactors( 6 );
		Actions\expectDone( UserFactors::CHANGED_ACTION )->twice()->with( 6, 'added', 'totp' );
		Actions\expectDone( UserFactors::CHANGED_ACTION )->once()->with( 6, 'removed', 'totp' );
		Actions\expectDone( UserFactors::CHANGED_ACTION )->once()->with( 6, 'added', 'passkey' );
		Actions\expectDone( UserFactors::CHANGED_ACTION )->once()->with( 6, 'removed', 'passkey' );
		Actions\expectDone( UserFactors::CHANGED_ACTION )->once()->with( 6, 'removed', 'all' );

		$factors->save_totp( self::SECRET );
		$factors->delete_totp();
		$factors->delete_totp(); // Nothing left: no second notice.
		$record = new PasskeyRecord( str_repeat( 'a', 64 ), 'cred', 'PEM', 0, 'Key', 1, 0 );
		$factors->add_passkey( $record );
		$factors->remove_passkey( $record->id );
		$factors->save_totp( self::SECRET );
		$factors->reset_all();
		$this->addToAssertionCount( 5 );
	}

	public function test_a_reset_without_factors_is_silent(): void {
		Actions\expectDone( UserFactors::CHANGED_ACTION )->never();

		( new UserFactors( 6 ) )->reset_all();
		$this->addToAssertionCount( 1 );
	}

	public function test_the_added_mail_names_the_change_but_no_secret(): void {
		( new FactorNotifier() )->notify( 6, 'added', 'totp' );

		$this->assertCount( 1, $this->mails );
		list( $to, $subject, $body ) = $this->mails[0];
		$this->assertSame( 'bob@example.com', $to );
		$this->assertStringContainsString( 'Example & Co', $subject );
		$this->assertStringContainsString( 'An authenticator app was set up', $body );
		$this->assertStringContainsString( 'UTC', $body );
		$this->assertStringContainsString( '2001:db8:1:2::/64', $body );
		$this->assertStringContainsString( 'contact an administrator', $body );
		$this->assertStringNotContainsString( self::SECRET, $subject . $body );
		$this->assertDoesNotMatchRegularExpression( '/\b[0-9]{6}\b|[2-9a-z]{4}-[2-9a-z]{4}/', $body, 'No codes.' );
	}

	public function test_the_removed_mail(): void {
		( new FactorNotifier() )->notify( 6, 'removed', 'passkey' );
		( new FactorNotifier() )->notify( 6, 'removed', 'all' );

		$this->assertStringContainsString( 'A passkey was removed', $this->mails[0][2] );
		$this->assertStringContainsString( 'All two-factor sign-in methods were removed', $this->mails[1][2] );
	}

	public function test_the_recovery_and_devices_mails_carry_no_codes(): void {
		( new FactorNotifier() )->notify( 6, 'regenerated', 'recovery' );
		( new FactorNotifier() )->notify( 6, 'forgotten', 'devices' );

		$this->assertCount( 2, $this->mails );
		$this->assertStringContainsString( 'New recovery codes were created', $this->mails[0][2] );
		$this->assertStringContainsString( 'Every remembered device was signed out', $this->mails[1][2] );
		foreach ( $this->mails as $mail ) {
			$this->assertSame( 'bob@example.com', $mail[0] );
			$this->assertDoesNotMatchRegularExpression( '/[2-9a-z]{4}-[2-9a-z]{4}/', $mail[2], 'No recovery code in the mail.' );
		}
	}

	public function test_forgetting_devices_through_the_action_does_not_loop(): void {
		$calls = 0;
		Actions\expectDone( UserFactors::CHANGED_ACTION )->once()->whenHappen(
			static function () use ( &$calls ) {
				++$calls;
			}
		);
		do_action( UserFactors::CHANGED_ACTION, 6, 'forgotten', 'devices' );
		( new \LightweightPlugins\Firewall\TwoFactor\RememberRevoker() )->on_factor_changed( 6 );

		$this->assertSame( 1, $calls, 'Rotating the salt fires no further change action.' );
	}

	public function test_no_mail_without_an_address_or_user(): void {
		( new FactorNotifier() )->notify( 99, 'added', 'totp' );
		$this->assertSame( array(), $this->mails );
	}

	public function test_the_notifier_listens_to_the_change_action(): void {
		$notifier = new FactorNotifier();
		$notifier->register();

		$this->assertSame( 10, has_action( UserFactors::CHANGED_ACTION, array( $notifier, 'notify' ) ) );
	}

	// ---- mail failure notice --------------------------------------------------

	private function notice_html( bool $admin ): string {
		Functions\when( 'current_user_can' )->justReturn( $admin );
		ob_start();
		( new MailFailureNotice() )->render();
		return (string) ob_get_clean();
	}

	public function test_the_mail_failure_notice_is_for_administrators_while_flagged(): void {
		$this->assertSame( '', $this->notice_html( true ), 'Nothing flagged.' );

		update_option( EnrollmentMail::FAILED_OPTION, 123 );
		$this->assertSame( '', $this->notice_html( false ) );
		$html = $this->notice_html( true );
		$this->assertStringContainsString( 'dashicons-email-alt', $html );
		$this->assertStringContainsString( 'action=' . MailFailureNotice::ACTION . '&_wpnonce=n-' . MailFailureNotice::ACTION, $html );
	}

	public function test_the_dismiss_handler_is_registered(): void {
		$notice = new MailFailureNotice();
		$notice->register();

		$this->assertNotFalse( has_action( 'admin_post_' . MailFailureNotice::ACTION, array( $notice, 'dismiss' ) ) );
		$this->assertNotFalse( has_action( 'admin_notices', array( $notice, 'render' ) ) );
	}
}
