<?php
/**
 * Plugin Name:       Admin IP Lockdown
 * Plugin URI:        https://www.contentpowered.com
 * Description:       Restricts wp-admin and wp-login.php to allowed IP addresses, with Cloudflare support, dynamic DNS hostnames for home IPs that change, and an emergency email unlock link so you can't lock yourself out.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.2
 * Author:            Content Powered
 * Author URI:        https://www.contentpowered.com/wordpress-plugins/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       admin-ip-lockdown
 * Update URI:        https://github.com/jmsprsns/admin-ip-lockdown
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

// Version and repo are read from the header above, so a release only needs
// "Version" bumped and the GitHub repo lives in one place ("Update URI").
// The Update URI header also stops WordPress.org offering a same-slug plugin
// as an "update" that would overwrite this one.
$admin_ip_lockdown_headers = get_file_data(
	__FILE__,
	array(
		'version' => 'Version',
		'repo'    => 'Update URI',
	)
);

define( 'ADMIN_IP_LOCKDOWN_VERSION', $admin_ip_lockdown_headers['version'] );
define( 'ADMIN_IP_LOCKDOWN_REPO', $admin_ip_lockdown_headers['repo'] );
define( 'ADMIN_IP_LOCKDOWN_FILE', __FILE__ );
define( 'ADMIN_IP_LOCKDOWN_DIR', plugin_dir_path( __FILE__ ) );
define( 'ADMIN_IP_LOCKDOWN_URL', plugin_dir_url( __FILE__ ) );

unset( $admin_ip_lockdown_headers );

require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-icons.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-updater.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-menu.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-feedback.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-ip.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-cloudflare.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-request.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-dns.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-access.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-log.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-unlock.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-blocked.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-guard.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-admin.php';
require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-plugin.php';

// Built right away, outside any hook, so WP-Cron background updates and
// remote management tools see new releases too (not only logged-in admins).
Admin_IP_Lockdown_Updater::init();

// The guard hooks in now, not on plugins_loaded: WordPress can work out who
// is signed in as soon as every plugin has loaded, and the lockdown has to
// be listening by then.
Admin_IP_Lockdown_Guard::init();

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once ADMIN_IP_LOCKDOWN_DIR . 'includes/class-admin-ip-lockdown-cli.php';
	WP_CLI::add_command( 'admin-ip-lockdown', 'Admin_IP_Lockdown_CLI' );
}

/**
 * Boot the plugin once all other plugins have loaded.
 *
 * @return Admin_IP_Lockdown_Plugin
 */
function admin_ip_lockdown_plugin() {
	return Admin_IP_Lockdown_Plugin::instance();
}
add_action( 'plugins_loaded', 'admin_ip_lockdown_plugin' );

/**
 * Set up on activation: the log table, the settings with the activating
 * admin's own address already on the list, and the scheduled jobs. The
 * lockdown itself stays off until it's switched on from the settings page.
 *
 * @return void
 */
function admin_ip_lockdown_activate() {
	Admin_IP_Lockdown_Plugin::activate();
}
register_activation_hook( ADMIN_IP_LOCKDOWN_FILE, 'admin_ip_lockdown_activate' );

/**
 * Clean up when the plugin is deactivated.
 *
 * The lockdown stops with the plugin. Settings, the allowed list and the log
 * stay put (uninstall.php removes them), so switching it back on restores
 * the same list.
 *
 * @return void
 */
function admin_ip_lockdown_deactivate() {
	wp_clear_scheduled_hook( Admin_IP_Lockdown_Plugin::CRON_DAILY );
	wp_clear_scheduled_hook( Admin_IP_Lockdown_Plugin::CRON_CLOUDFLARE );
}
register_deactivation_hook( ADMIN_IP_LOCKDOWN_FILE, 'admin_ip_lockdown_deactivate' );
