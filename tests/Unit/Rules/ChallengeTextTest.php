<?php
/**
 * Tests for the challenge page text.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Tests\Unit\Rules;

use LightweightPlugins\Firewall\Rules\ChallengeText;
use PHPUnit\Framework\TestCase;

/**
 * @covers \LightweightPlugins\Firewall\Rules\ChallengeText
 */
final class ChallengeTextTest extends TestCase {

	public function test_cart_challenge_talks_about_the_cart(): void {
		$this->assertSame( 'Continue without adding to the cart', ChallengeText::defaults( ChallengeText::CART )['link'] );
	}

	public function test_filter_challenge_talks_about_filters(): void {
		$this->assertSame( 'Continue without filters', ChallengeText::defaults( ChallengeText::FILTER )['link'] );
	}
}
