<?php
/**
 * Plugin Name: LW Firewall
 * Plugin URI:  https://github.com/lwplugins/lw-firewall
 * Description: Lightweight firewall — rate-limits endpoints, blocks bots, bans repeat offenders, and adds security headers.
 * Version:     1.1.4
 * Author:      LW Plugins
 * Author URI:  https://lwplugins.com
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: lw-firewall
 * Requires at least: 6.0
 * Requires PHP: 8.1
 *
 * @package LightweightPlugins\Firewall
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'LW_FIREWALL_VERSION', '1.1.4' );
define( 'LW_FIREWALL_FILE', __FILE__ );
define( 'LW_FIREWALL_PATH', plugin_dir_path( __FILE__ ) );
define( 'LW_FIREWALL_URL', plugin_dir_url( __FILE__ ) );

/**
 * PSR-4 autoloader for LightweightPlugins\Firewall namespace.
 */
spl_autoload_register(
	static function ( string $class_name ): void {
		$prefix = 'LightweightPlugins\\Firewall\\';

		if ( ! str_starts_with( $class_name, $prefix ) ) {
			return;
		}

		$relative = substr( $class_name, strlen( $prefix ) );
		$file     = LW_FIREWALL_PATH . 'includes/' . str_replace( '\\', '/', $relative ) . '.php';

		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}
);

/**
 * Factory function — singleton Plugin instance.
 */
function lw_firewall(): LightweightPlugins\Firewall\Plugin {
	static $instance = null;

	if ( null === $instance ) {
		$instance = new LightweightPlugins\Firewall\Plugin();
	}

	return $instance;
}

// Activation / deactivation hooks.
register_activation_hook( __FILE__, [ LightweightPlugins\Firewall\Activator::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ LightweightPlugins\Firewall\Activator::class, 'deactivate' ] );

// WP-CLI command registration.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'lw-firewall', LightweightPlugins\Firewall\CLI\FirewallCommand::class );
	WP_CLI::add_command( 'lw-firewall config', LightweightPlugins\Firewall\CLI\ConfigCommand::class );
	WP_CLI::add_command( 'lw-firewall bots', LightweightPlugins\Firewall\CLI\BotsCommand::class );
	WP_CLI::add_command( 'lw-firewall logs', LightweightPlugins\Firewall\CLI\LogsCommand::class );
	WP_CLI::add_command( 'lw-firewall worker', LightweightPlugins\Firewall\CLI\WorkerCommand::class );
	WP_CLI::add_command( 'lw-firewall ip', LightweightPlugins\Firewall\CLI\IpCommand::class );
}

// Bootstrap on plugins_loaded.
add_action( 'plugins_loaded', 'lw_firewall' );

/**
 * Resolve the storage backend instance.
 *
 * Shared helper used by both the main plugin and the MU-plugin worker.
 *
 * @param string $preference Storage preference ('auto', 'apcu', 'redis', 'file').
 * @return LightweightPlugins\Firewall\Storage\StorageInterface
 */
function lw_firewall_resolve_storage( string $preference ): LightweightPlugins\Firewall\Storage\StorageInterface {
	if ( 'apcu' === $preference && LightweightPlugins\Firewall\Storage\ApcuStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\ApcuStorage();
	}

	if ( 'redis' === $preference && LightweightPlugins\Firewall\Storage\RedisStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\RedisStorage();
	}

	if ( 'file' === $preference ) {
		return new LightweightPlugins\Firewall\Storage\FileStorage();
	}

	// Auto-detect: apcu > redis > file.
	if ( LightweightPlugins\Firewall\Storage\ApcuStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\ApcuStorage();
	}

	if ( LightweightPlugins\Firewall\Storage\RedisStorage::is_available() ) {
		return new LightweightPlugins\Firewall\Storage\RedisStorage();
	}

	return new LightweightPlugins\Firewall\Storage\FileStorage();
}
