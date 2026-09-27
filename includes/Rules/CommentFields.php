<?php
/**
 * Comment form fields: honeypot, proof-of-render token and its refresh.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Rules;

use LightweightPlugins\Firewall\Options;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the hidden fields into every comment_form() output — classic theme
 * comment templates, the block theme `core/post-comments-form` block and both
 * WooCommerce review forms (the classic template and the Product Review Form
 * block) all call comment_form(), which fires the `comment_form` action just
 * before `</form>`.
 *
 * Full-page caching hands one rendered token to every visitor for as long as
 * the page stays cached. The token is therefore never single-use here, its
 * lifetime is generous, and a small script swaps a stale token for a fresh one
 * the first time the visitor focuses the form — one uncached request per
 * commenter, not per page view.
 */
final class CommentFields {

	public const TOKEN_FIELD    = 'lw_fw_comment_token';
	public const HONEYPOT_FIELD = 'lw_fw_hp_website';
	public const AJAX_ACTION    = 'lw_fw_comment_token';

	private const SCRIPT_HANDLE = 'lw-firewall-comment-token';

	/**
	 * Visually hidden without display:none (which many bots skip) and without
	 * an off-screen offset (which scrolls sideways on right-to-left pages).
	 */
	private const HIDDEN_STYLE = 'position:absolute!important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);clip-path:inset(50%);white-space:nowrap;border:0;';

	/**
	 * Forms rendered in this request, for unique element IDs.
	 *
	 * @var int
	 */
	private static int $count = 0;

	/**
	 * Register the render and token-refresh hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'comment_form', [ self::class, 'render' ] );

		if ( self::token_enabled() ) {
			add_action( 'wp_ajax_' . self::AJAX_ACTION, [ self::class, 'refresh' ] );
			add_action( 'wp_ajax_nopriv_' . self::AJAX_ACTION, [ self::class, 'refresh' ] );
		}
	}

	/**
	 * Print the honeypot and token fields inside the comment form.
	 *
	 * @return void
	 */
	public static function render(): void {
		++self::$count;

		if ( ! empty( Options::get( 'comment_honeypot' ) ) ) {
			$id = 'lw-fw-hp-' . self::$count;

			printf(
				'<p class="lw-fw-hp" aria-hidden="true" style="%1$s"><label for="%2$s">%3$s</label><input type="text" id="%2$s" name="%4$s" value="" tabindex="-1" autocomplete="off" /></p>',
				esc_attr( self::HIDDEN_STYLE ),
				esc_attr( $id ),
				esc_html__( 'Leave this field empty', 'lw-firewall' ),
				esc_attr( self::HONEYPOT_FIELD )
			);
		}

		if ( ! self::token_enabled() ) {
			return;
		}

		printf(
			'<input type="hidden" name="%s" value="%s" data-lw-fw-issued="%d" data-lw-fw-stale="%d" data-lw-fw-refresh="%s" />',
			esc_attr( self::TOKEN_FIELD ),
			esc_attr( RegisterToken::issue( CommentSpamCheck::SCOPE ) ),
			(int) time(),
			(int) self::stale_after(),
			esc_url( admin_url( 'admin-ajax.php' ) )
		);

		wp_enqueue_script(
			self::SCRIPT_HANDLE,
			LW_FIREWALL_URL . 'assets/js/comment-token.js',
			[],
			LW_FIREWALL_VERSION,
			[
				'in_footer' => true,
				'strategy'  => 'defer',
			]
		);
	}

	/**
	 * AJAX: hand out a fresh token (the stale-cached-page refresh).
	 *
	 * Public and read-only: it proves no more than loading an uncached page
	 * would, which is exactly what the token is meant to prove.
	 *
	 * @return void
	 */
	public static function refresh(): void {
		nocache_headers();

		wp_send_json_success(
			[
				'token'  => RegisterToken::issue( CommentSpamCheck::SCOPE ),
				'issued' => time(),
			]
		);
	}

	/**
	 * Token age, in seconds, after which the script fetches a fresh one:
	 * half the lifetime, so a refreshed token outlives any realistic form
	 * session even with some client clock skew.
	 *
	 * @return int
	 */
	private static function stale_after(): int {
		return max( 60, intdiv( (int) Options::get( 'comment_token_max_age', DAY_IN_SECONDS ), 2 ) );
	}

	/**
	 * Whether the signed token is part of the protection.
	 *
	 * @return bool
	 */
	private static function token_enabled(): bool {
		return ! empty( Options::get( 'comment_token_enabled' ) );
	}
}
