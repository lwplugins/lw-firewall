<?php
/**
 * Cache directory hygiene.
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

namespace LightweightPlugins\Firewall\Storage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Keeps the file cache directory unreachable and unbounded-growth free.
 *
 * Separate from FileStorage because this changes for its own reasons — a new
 * web server needing a different guard file, a different sweep budget — none of
 * which are about reading or writing a counter.
 */
final class CacheDirectory {

	/**
	 * One in this many instantiations runs a sweep.
	 */
	private const SWEEP_ODDS = 200;

	/**
	 * Files examined per sweep, so one unlucky request never pays much.
	 */
	private const SWEEP_BATCH = 300;

	/**
	 * Drop the guard files into a cache directory.
	 *
	 * Unconditional, and public, because the guard used to be written only when
	 * this constructor happened to create the directory — and the geo updater
	 * creates the same parent with wp_mkdir_p(). Whichever ran first decided
	 * whether the directory was protected at all. The key names are predictable
	 * (ban_<ip>, 404_<ip>), so a served directory leaks who is banned.
	 *
	 * @param string $dir Directory to protect.
	 * @return void
	 */
	public static function protect( string $dir ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}

		$guards = [
			'.htaccess' => "Deny from all\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n",
			'index.php' => "<?php\n// Silence is golden.\n",
		];

		foreach ( $guards as $name => $contents ) {
			if ( ! file_exists( $dir . $name ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- An unwritable cache directory must not fatal a page load.
				@file_put_contents( $dir . $name, $contents );
			}
		}
	}

	/**
	 * Occasionally delete expired files.
	 *
	 * An expired file was only removed if the very same hashed key was read
	 * again, so distributed traffic and single-use tokens left files behind
	 * forever — thousands of dead inodes, none of them ever reclaimed. This is
	 * a cheap probabilistic sweep with a hard batch cap, so no single request
	 * pays much and the directory still converges.
	 *
	 * @param string $dir Directory to sweep.
	 * @return void
	 */
	public static function sweep( string $dir ): void {
		if ( 0 !== random_int( 0, self::SWEEP_ODDS - 1 ) ) {
			return;
		}

		$files = glob( $dir . '*.cache' );

		if ( ! is_array( $files ) ) {
			return;
		}

		$now     = time();
		$checked = 0;

		foreach ( $files as $file ) {
			if ( ++$checked > self::SWEEP_BATCH ) {
				return;
			}

			$data = self::read( $file );

			if ( null === $data ) {
				continue;
			}

			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize, WordPress.PHP.NoSilencedErrors.Discouraged -- A half-written cache file is an expected race; objects are refused outright.
			$entry = @unserialize( $data, [ 'allowed_classes' => false ] );

			if ( is_array( $entry ) && isset( $entry['expires'] ) && $entry['expires'] > 0 && $entry['expires'] < $now ) {
				wp_delete_file( $file );
			}
		}
	}

	/**
	 * Read a file under a shared lock.
	 *
	 * @param string $file Absolute path.
	 * @return string|null Raw contents, or null when unreadable.
	 */
	private static function read( string $file ): ?string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.PHP.NoSilencedErrors.Discouraged -- A vanished or unreadable cache file is an expected race, not an error to surface.
		$handle = @fopen( $file, 'rb' );

		if ( false === $handle ) {
			return null;
		}

		try {
			if ( ! flock( $handle, LOCK_SH ) ) {
				return null;
			}

			$size = (int) filesize( $file );

			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
			$data = $size > 0 ? fread( $handle, $size ) : '';

			return false === $data ? null : $data;
		} finally {
			flock( $handle, LOCK_UN );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			fclose( $handle );
		}
	}
}
