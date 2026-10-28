<?php
/**
 * Runs when the plugin is deleted from the Plugins screen: remove its data.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Remove the plugin's data from the current site.
 *
 * @return void
 */
function admin_ip_lockdown_uninstall_site() {
	global $wpdb;

	foreach ( array( 'settings', 'dns', 'temporary', 'cloudflare', 'events', 'db', 'unlock_rate' ) as $admin_ip_lockdown_option ) {
		delete_option( 'admin_ip_lockdown_' . $admin_ip_lockdown_option );
	}

	delete_transient( 'admin_ip_lockdown_dns_lock' );

	wp_clear_scheduled_hook( 'admin_ip_lockdown_daily' );
	wp_clear_scheduled_hook( 'admin_ip_lockdown_cloudflare_refresh' );

	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}ailock_log" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Removing the plugin's own table.
}

if ( is_multisite() ) {
	foreach ( get_sites(
		array(
			'fields' => 'ids',
			'number' => 10000,
		)
	) as $admin_ip_lockdown_site ) {
		switch_to_blog( (int) $admin_ip_lockdown_site );
		admin_ip_lockdown_uninstall_site();
		restore_current_blog();
	}
} else {
	admin_ip_lockdown_uninstall_site();
}

// Unlock links waiting to be used, and when each account last got one.
delete_metadata( 'user', 0, 'admin_ip_lockdown_unlock', '', true );
delete_metadata( 'user', 0, 'admin_ip_lockdown_unlock_sent', '', true );

// Plugin Update Checker's cached update state.
delete_site_option( 'external_updates-admin-ip-lockdown' );
