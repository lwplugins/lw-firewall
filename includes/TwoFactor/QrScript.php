<?php
/**
 * The shared QR code script (build/qr.js).
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\TwoFactor;

use LightweightPlugins\Firewall\Admin\BuildAssets;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Used by the profile screen and the forced-enrollment screen. The script
 * exposes window.lwFirewallQr and draws an SVG QR code into every element
 * with a `data-lwfw-qr` attribute; the key and the otpauth link stay on the
 * page as the fallback.
 */
final class QrScript {

	public const HANDLE = 'lw-firewall-qr';

	/**
	 * Data attribute holding the text to encode.
	 */
	public const ATTRIBUTE = 'data-lwfw-qr';

	/**
	 * Enqueue the script (footer).
	 *
	 * @return bool False when the build or the plugin constants are missing.
	 */
	public static function enqueue(): bool {
		if ( ! defined( 'LW_FIREWALL_PATH' ) || ! defined( 'LW_FIREWALL_URL' ) ) {
			return false;
		}

		return BuildAssets::enqueue( 'qr', self::HANDLE );
	}
}
