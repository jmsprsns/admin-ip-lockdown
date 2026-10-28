<?php
/**
 * WP-CLI commands: another way back in for anyone with shell access.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Manage Admin IP Lockdown: see the status, edit the allowed list, switch
 * the lockdown on or off.
 */
final class Admin_IP_Lockdown_CLI {

	/**
	 * Show whether the lockdown is on and what's allowed.
	 *
	 * ## EXAMPLES
	 *
	 *     wp admin-ip-lockdown status
	 *
	 * @return void
	 */
	public function status() {
		$settings = Admin_IP_Lockdown_Plugin::settings();

		if ( Admin_IP_Lockdown_Plugin::disabled_by_constant() ) {
			WP_CLI::log( 'Lockdown: off (ADMIN_IP_LOCKDOWN_DISABLE is set in wp-config.php)' );
		} else {
			WP_CLI::log( 'Lockdown: ' . ( Admin_IP_Lockdown_Plugin::enforcing() ? 'on' : 'off' ) );
		}

		$rows = array();

		foreach ( $settings['entries'] as $entry ) {
			$rows[] = array(
				'entry'  => $entry['value'],
				'type'   => $entry['type'],
				'label'  => $entry['label'],
				'source' => 'list',
				'detail' => 'host' === $entry['type'] ? implode( ', ', Admin_IP_Lockdown_DNS::ips( $entry['value'] ) ) : '',
			);
		}

		foreach ( Admin_IP_Lockdown_Access::config_entries() as $entry ) {
			$rows[] = array(
				'entry'  => $entry['value'],
				'type'   => $entry['type'],
				'label'  => '',
				'source' => 'wp-config.php',
				'detail' => 'host' === $entry['type'] ? implode( ', ', Admin_IP_Lockdown_DNS::ips( $entry['value'] ) ) : '',
			);
		}

		foreach ( Admin_IP_Lockdown_Access::temporary() as $item ) {
			$rows[] = array(
				'entry'  => $item['value'],
				'type'   => 'temporary',
				'label'  => '',
				'source' => 'unlock link',
				'detail' => 'until ' . wp_date( 'Y-m-d H:i', $item['expires'] ),
			);
		}

		if ( ! $rows ) {
			WP_CLI::log( 'Nothing is on the allowed list.' );
			return;
		}

		WP_CLI\Utils\format_items( 'table', $rows, array( 'entry', 'type', 'label', 'source', 'detail' ) );
	}

	/**
	 * Add an IP address, range or hostname to the allowed list.
	 *
	 * ## OPTIONS
	 *
	 * <entry>
	 * : An IPv4 or IPv6 address, a range (203.0.113.0/24 or 203.0.113.*) or a hostname.
	 *
	 * [--label=<label>]
	 * : A note to remember it by.
	 *
	 * ## EXAMPLES
	 *
	 *     wp admin-ip-lockdown allow 203.0.113.24 --label="Office"
	 *     wp admin-ip-lockdown allow home.example.duckdns.org
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Named arguments.
	 * @return void
	 */
	public function allow( $args, $assoc_args ) {
		$parsed = Admin_IP_Lockdown_IP::parse_entry( $args[0] );

		if ( is_wp_error( $parsed ) ) {
			WP_CLI::error( $parsed->get_error_message() );
		}

		$settings = Admin_IP_Lockdown_Plugin::settings();

		foreach ( $settings['entries'] as $entry ) {
			if ( $entry['value'] === $parsed['value'] ) {
				WP_CLI::success( $parsed['value'] . ' is already on the list.' );
				return;
			}
		}

		if ( count( $settings['entries'] ) >= Admin_IP_Lockdown_Plugin::MAX_ENTRIES ) {
			WP_CLI::error( 'The list is full.' );
		}

		if ( 'host' === $parsed['type'] && count( Admin_IP_Lockdown_Access::hosts( $settings ) ) >= Admin_IP_Lockdown_Plugin::MAX_HOSTS ) {
			WP_CLI::error( sprintf( 'At most %d hostnames can be on the list.', Admin_IP_Lockdown_Plugin::MAX_HOSTS ) );
		}

		$settings['entries'][] = array(
			'type'  => $parsed['type'],
			'value' => $parsed['value'],
			'label' => isset( $assoc_args['label'] ) ? substr( sanitize_text_field( $assoc_args['label'] ), 0, 60 ) : '',
			'added' => time(),
		);

		update_option( Admin_IP_Lockdown_Plugin::OPTION, $settings );

		if ( 'host' === $parsed['type'] ) {
			Admin_IP_Lockdown_DNS::refresh( array( $parsed['value'] ), true );
			$ips = Admin_IP_Lockdown_DNS::ips( $parsed['value'] );
			WP_CLI::log( $ips ? 'Resolves to ' . implode( ', ', $ips ) : 'Warning: it doesn\'t resolve right now.' );
		}

		WP_CLI::success( 'Added ' . $parsed['value'] . '.' );
	}

	/**
	 * Remove an entry from the allowed list, or end a network's temporary access.
	 *
	 * ## OPTIONS
	 *
	 * <entry>
	 * : The entry as the status command shows it.
	 *
	 * ## EXAMPLES
	 *
	 *     wp admin-ip-lockdown remove 203.0.113.24
	 *
	 * @param array $args Positional arguments.
	 * @return void
	 */
	public function remove( $args ) {
		$parsed   = Admin_IP_Lockdown_IP::parse_entry( $args[0] );
		$value    = is_wp_error( $parsed ) ? trim( (string) $args[0] ) : $parsed['value'];
		$settings = Admin_IP_Lockdown_Plugin::settings();
		$kept     = array();

		foreach ( $settings['entries'] as $entry ) {
			if ( $entry['value'] !== $value ) {
				$kept[] = $entry;
			}
		}

		if ( count( $kept ) !== count( $settings['entries'] ) ) {
			$settings['entries'] = $kept;
			update_option( Admin_IP_Lockdown_Plugin::OPTION, $settings );
			WP_CLI::success( 'Removed ' . $value . '.' );
			return;
		}

		if ( Admin_IP_Lockdown_Access::remove_temporary( $value ) ) {
			Admin_IP_Lockdown_Log::event( 'removed', 0, $value );
			WP_CLI::success( 'Ended temporary access for ' . $value . '.' );
			return;
		}

		WP_CLI::error( $value . ' isn\'t on the list.' );
	}

	/**
	 * Switch the lockdown on.
	 *
	 * ## EXAMPLES
	 *
	 *     wp admin-ip-lockdown on
	 *
	 * @return void
	 */
	public function on() {
		$settings = Admin_IP_Lockdown_Plugin::settings();

		if ( ! Admin_IP_Lockdown_Access::has_entries( $settings ) ) {
			WP_CLI::error( 'Add an address first: wp admin-ip-lockdown allow <ip>' );
		}

		$settings['enabled'] = 1;
		update_option( Admin_IP_Lockdown_Plugin::OPTION, $settings );

		WP_CLI::warning( 'WP-CLI can\'t see your browser\'s IP address. Make sure yours is on the list (wp admin-ip-lockdown status).' );
		WP_CLI::success( 'Lockdown is on.' );
	}

	/**
	 * Switch the lockdown off. The allowed list is kept.
	 *
	 * ## EXAMPLES
	 *
	 *     wp admin-ip-lockdown off
	 *
	 * @return void
	 */
	public function off() {
		$settings            = Admin_IP_Lockdown_Plugin::settings();
		$settings['enabled'] = 0;
		update_option( Admin_IP_Lockdown_Plugin::OPTION, $settings );

		WP_CLI::success( 'Lockdown is off. wp-admin and the login page are open to every address again.' );
	}
}
