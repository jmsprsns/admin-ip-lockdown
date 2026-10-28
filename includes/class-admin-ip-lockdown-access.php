<?php
/**
 * Decides whether an address is allowed in.
 *
 * An address gets in when it matches any of:
 * - the allowed list on the settings page (addresses, ranges, hostnames),
 * - addresses set in wp-config.php (ADMIN_IP_LOCKDOWN_ALLOW), handy for an
 *   agency's office IP across every client site,
 * - a network unlocked for a while by an emailed unlock link.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Allowed-list matching.
 */
final class Admin_IP_Lockdown_Access {

	/**
	 * Option holding temporary access from unlock links.
	 */
	const TEMPORARY = 'admin_ip_lockdown_temporary';

	/**
	 * Most networks with temporary access at once.
	 */
	const MAX_TEMPORARY = 50;

	/**
	 * Decisions for the live settings, per address, for this request.
	 *
	 * @var array<string,array|null>
	 */
	private static $memo = array();

	/**
	 * Forget remembered decisions (after the list changes).
	 *
	 * @return void
	 */
	public static function reset() {
		self::$memo = array();
	}

	/**
	 * Entries from ADMIN_IP_LOCKDOWN_ALLOW in wp-config.php: a string of
	 * addresses, ranges and hostnames separated by commas, spaces or new
	 * lines, or an array of them.
	 *
	 * @param bool $with_invalid Also return the ones that couldn't be read.
	 * @return array List of entries, or {valid, invalid} with $with_invalid.
	 */
	public static function config_entries( $with_invalid = false ) {
		$valid   = array();
		$invalid = array();

		if ( defined( 'ADMIN_IP_LOCKDOWN_ALLOW' ) ) {
			$raw   = ADMIN_IP_LOCKDOWN_ALLOW;
			$items = is_array( $raw ) ? $raw : preg_split( '/[\s,;]+/', (string) $raw, -1, PREG_SPLIT_NO_EMPTY );

			foreach ( array_slice( (array) $items, 0, Admin_IP_Lockdown_Plugin::MAX_ENTRIES ) as $item ) {
				$parsed = is_scalar( $item ) ? Admin_IP_Lockdown_IP::parse_entry( (string) $item ) : new WP_Error( 'invalid', '' );

				if ( is_wp_error( $parsed ) ) {
					$invalid[] = is_scalar( $item ) ? (string) $item : '';
					continue;
				}

				$parsed['label'] = 'wp-config.php';
				$valid[]         = $parsed;
			}
		}

		return $with_invalid ? array(
			'valid'   => $valid,
			'invalid' => $invalid,
		) : $valid;
	}

	/**
	 * Networks with temporary access that hasn't run out yet.
	 *
	 * @return array<int,array{value:string,user:int,expires:int,created:int,ip:string}>
	 */
	public static function temporary() {
		$saved = get_option( self::TEMPORARY, array() );
		$now   = time();
		$live  = array();

		if ( ! is_array( $saved ) ) {
			return array();
		}

		foreach ( $saved as $item ) {
			if ( is_array( $item ) && isset( $item['value'], $item['expires'] ) && (int) $item['expires'] > $now ) {
				$live[] = array(
					'value'   => (string) $item['value'],
					'user'    => isset( $item['user'] ) ? (int) $item['user'] : 0,
					'expires' => (int) $item['expires'],
					'created' => isset( $item['created'] ) ? (int) $item['created'] : 0,
					'ip'      => isset( $item['ip'] ) ? (string) $item['ip'] : '',
				);
			}
		}

		return $live;
	}

	/**
	 * Give a network access for a while. Unlocking the same network again
	 * extends it.
	 *
	 * @param string $ip      The visitor's address. IPv6 unlocks its /64.
	 * @param int    $user_id Who unlocked it.
	 * @param int    $seconds How long.
	 * @return array|false The stored item.
	 */
	public static function add_temporary( $ip, $user_id, $seconds ) {
		$ip    = Admin_IP_Lockdown_IP::normalize( $ip );
		$value = Admin_IP_Lockdown_IP::is_v6( $ip ) ? Admin_IP_Lockdown_IP::network64( $ip ) : $ip;

		if ( '' === $value ) {
			return false;
		}

		$items = array();

		foreach ( self::temporary() as $item ) {
			if ( $item['value'] !== $value ) {
				$items[] = $item;
			}
		}

		$item = array(
			'value'   => $value,
			'user'    => (int) $user_id,
			'expires' => time() + max( 60, (int) $seconds ),
			'created' => time(),
			'ip'      => $ip,
		);

		$items[] = $item;
		$items   = array_slice( $items, -self::MAX_TEMPORARY );

		update_option( self::TEMPORARY, $items, true );
		self::reset();

		return $item;
	}

	/**
	 * End a network's temporary access.
	 *
	 * @param string $value Address or /64 as stored.
	 * @return array|null The removed item.
	 */
	public static function remove_temporary( $value ) {
		$removed = null;
		$items   = array();

		foreach ( self::temporary() as $item ) {
			if ( $item['value'] === $value ) {
				$removed = $item;
			} else {
				$items[] = $item;
			}
		}

		update_option( self::TEMPORARY, $items, true );
		self::reset();

		return $removed;
	}

	/**
	 * Drop expired temporary access (daily).
	 *
	 * @return void
	 */
	public static function prune_temporary() {
		$saved = get_option( self::TEMPORARY, array() );
		$live  = self::temporary();

		if ( ! is_array( $saved ) || count( $saved ) !== count( $live ) ) {
			update_option( self::TEMPORARY, $live, true );
		}
	}

	/**
	 * Every hostname on the settings list and in wp-config.php.
	 *
	 * @param array $settings Plugin settings.
	 * @return string[]
	 */
	public static function hosts( array $settings ) {
		$hosts = array();

		foreach ( array_merge( $settings['entries'], self::config_entries() ) as $entry ) {
			if ( 'host' === $entry['type'] ) {
				$hosts[] = $entry['value'];
			}
		}

		return array_values( array_unique( $hosts ) );
	}

	/**
	 * Whether there's anything to let anyone in. With nothing at all on any
	 * list the lockdown doesn't run, rather than shut every door.
	 *
	 * @param array $settings Plugin settings.
	 * @return bool
	 */
	public static function has_entries( array $settings ) {
		return ! empty( $settings['entries'] ) || (bool) self::config_entries() || (bool) self::temporary();
	}

	/**
	 * What lets an address in, if anything.
	 *
	 * @param string $ip       Address.
	 * @param array  $settings Plugin settings.
	 * @param bool   $refresh  Look hostnames up again (at most once a minute)
	 *                         when nothing else matches.
	 * @return array|null {source: list|config|temporary, entry} or null.
	 */
	public static function match( $ip, array $settings, $refresh = false ) {
		$ip = Admin_IP_Lockdown_IP::normalize( $ip );

		if ( '' === $ip ) {
			return null;
		}

		$sources = array(
			'list'   => $settings['entries'],
			'config' => self::config_entries(),
		);

		// Addresses and ranges first: no lookups needed.
		foreach ( $sources as $source => $entries ) {
			foreach ( $entries as $entry ) {
				if ( 'host' !== $entry['type'] && Admin_IP_Lockdown_IP::in_range( $ip, $entry['value'] ) ) {
					return array(
						'source' => $source,
						'entry'  => $entry,
					);
				}
			}
		}

		foreach ( self::temporary() as $item ) {
			if ( Admin_IP_Lockdown_IP::in_range( $ip, $item['value'] ) ) {
				return array(
					'source' => 'temporary',
					'entry'  => $item,
				);
			}
		}

		$found = self::match_hosts( $ip, $sources );

		if ( null === $found && $refresh && Admin_IP_Lockdown_DNS::refresh( self::hosts( $settings ) ) ) {
			$found = self::match_hosts( $ip, $sources );
		}

		return $found;
	}

	/**
	 * Match against the hostnames' cached addresses.
	 *
	 * @param string $ip      Address.
	 * @param array  $sources Entries by source.
	 * @return array|null
	 */
	private static function match_hosts( $ip, array $sources ) {
		foreach ( $sources as $source => $entries ) {
			foreach ( $entries as $entry ) {
				if ( 'host' === $entry['type'] && Admin_IP_Lockdown_IP::matches_resolved( $ip, Admin_IP_Lockdown_DNS::ips( $entry['value'] ) ) ) {
					return array(
						'source' => $source,
						'entry'  => $entry,
					);
				}
			}
		}

		return null;
	}

	/**
	 * Whether an address is allowed under the saved settings. Looks the
	 * hostnames up again (at most once a minute) before saying no.
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	public static function is_allowed( $ip ) {
		if ( ! array_key_exists( $ip, self::$memo ) ) {
			self::$memo[ $ip ] = self::match( $ip, Admin_IP_Lockdown_Plugin::settings(), true );
		}

		return null !== self::$memo[ $ip ];
	}
}
