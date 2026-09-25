<?php
/**
 * Renders the MU-plugin worker for this installation.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Writes the plugin's real directory name into the worker before it is
 * installed.
 *
 * The worker runs before WordPress can tell it where the plugin lives, and it
 * used to assume WP_PLUGIN_DIR . '/lw-firewall/'. Installed from a renamed
 * directory (a Git checkout, a "-main" zip, a second copy), it found no files,
 * bailed silently and left the site unprotected. The shipped worker carries
 * the default directory in one define; this rewrites that line only.
 */
final class WorkerTemplate {

	/**
	 * Directory name used when the real one cannot be written safely.
	 */
	public const DEFAULT_DIR = 'lw-firewall';

	/**
	 * The one line the renderer rewrites.
	 */
	private const PATTERN = "/^define\\( 'LW_FIREWALL_WORKER_DIR', '[^'\\n]*' \\);$/m";

	/**
	 * Render the worker source for a plugin directory name.
	 *
	 * An unsafe name (anything that could leave the string literal or the
	 * plugins directory) falls back to the default.
	 *
	 * @param string $source Worker source code.
	 * @param string $dir    Plugin directory name under WP_PLUGIN_DIR.
	 * @return string
	 */
	public static function render( string $source, string $dir ): string {
		if ( ! self::is_safe_dir( $dir ) ) {
			$dir = self::DEFAULT_DIR;
		}

		$rendered = preg_replace( self::PATTERN, "define( 'LW_FIREWALL_WORKER_DIR', '" . $dir . "' );", $source, 1 );

		return null === $rendered ? $source : $rendered;
	}

	/**
	 * The plugin directory name from plugin_basename() of the main file.
	 *
	 * @param string $basename E.g. "lw-firewall/lw-firewall.php".
	 * @return string
	 */
	public static function dir_from_basename( string $basename ): string {
		$dir = dirname( $basename );

		return self::is_safe_dir( $dir ) ? $dir : self::DEFAULT_DIR;
	}

	/**
	 * Whether a directory name can be embedded in the worker verbatim.
	 *
	 * @param string $dir Candidate.
	 * @return bool
	 */
	public static function is_safe_dir( string $dir ): bool {
		return 1 === preg_match( '/^[A-Za-z0-9._-]+$/D', $dir ) && '.' !== $dir && '..' !== $dir;
	}
}
