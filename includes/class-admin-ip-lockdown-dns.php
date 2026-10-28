<?php
/**
 * Dynamic DNS hostnames: what each one points at, kept in a small cache.
 *
 * A hostname on the allowed list (say home.example.duckdns.org) lets in
 * whatever address it points at right now. Lookups never happen on normal
 * requests: the cached addresses are used, and only when someone is about
 * to be blocked are the hostnames looked up again, at most once a minute
 * across the whole site. So when the home IP changes, the new one works
 * within a minute, and nobody can make the site run a lookup per request.
 *
 * If a lookup fails, the last addresses that worked are kept, so a DNS
 * hiccup never locks the owner out.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Hostname resolution cache.
 */
final class Admin_IP_Lockdown_DNS {

	/**
	 * Option holding the cache: host => {ips, checked, ok, error, changed}.
	 */
	const OPTION = 'admin_ip_lockdown_dns';

	/**
	 * Transient that stops two lookups running at once.
	 */
	const LOCK = 'admin_ip_lockdown_dns_lock';

	/**
	 * Seconds between lookups of the same hostname when someone is blocked.
	 */
	const RECHECK = 60;

	/**
	 * Most addresses kept per hostname.
	 */
	const MAX_IPS = 16;

	/**
	 * The cache.
	 *
	 * @return array<string,array>
	 */
	public static function cache() {
		$cache = get_option( self::OPTION, array() );

		return is_array( $cache ) ? $cache : array();
	}

	/**
	 * Cached addresses for a hostname.
	 *
	 * @param string $host Hostname.
	 * @return string[]
	 */
	public static function ips( $host ) {
		$cache = self::cache();

		return isset( $cache[ $host ]['ips'] ) && is_array( $cache[ $host ]['ips'] ) ? $cache[ $host ]['ips'] : array();
	}

	/**
	 * Look a hostname up now.
	 *
	 * @param string $host Hostname.
	 * @return array{ips:string[],error:string}
	 */
	public static function lookup( $host ) {
		$ips   = array();
		$error = '';

		if ( ! Admin_IP_Lockdown_IP::is_hostname( $host ) ) {
			return array(
				'ips'   => array(),
				'error' => __( 'Not a valid hostname.', 'admin-ip-lockdown' ),
			);
		}

		// The trailing dot stops the server's search domains being tried.
		$fqdn = $host . '.';

		if ( function_exists( 'dns_get_record' ) ) {
			$records = @dns_get_record( $fqdn, DNS_A + DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Lookup failures are reported below.

			if ( is_array( $records ) ) {
				foreach ( $records as $record ) {
					foreach ( array( 'ip', 'ipv6' ) as $field ) {
						if ( isset( $record[ $field ] ) ) {
							$ips[] = Admin_IP_Lockdown_IP::normalize( $record[ $field ] );
						}
					}
				}
			}
		}

		// Some hosts disable dns_get_record(); the system resolver still answers IPv4.
		if ( ! $ips && function_exists( 'gethostbynamel' ) ) {
			$v4 = @gethostbynamel( $fqdn ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Lookup failures are reported below.

			if ( is_array( $v4 ) ) {
				$ips = array_map( array( 'Admin_IP_Lockdown_IP', 'normalize' ), $v4 );
			}
		}

		$ips = array_slice( array_values( array_unique( array_filter( $ips ) ) ), 0, self::MAX_IPS );

		if ( ! $ips ) {
			$error = __( 'The hostname didn\'t resolve to any address.', 'admin-ip-lockdown' );
		}

		return array(
			'ips'   => $ips,
			'error' => $error,
		);
	}

	/**
	 * Look hostnames up again and store the results.
	 *
	 * @param string[] $hosts Hostnames to check.
	 * @param bool     $force Look up even ones checked within the last minute.
	 * @return bool Whether any hostname's addresses changed.
	 */
	public static function refresh( array $hosts, $force = false ) {
		$hosts = array_values( array_unique( array_filter( $hosts, array( 'Admin_IP_Lockdown_IP', 'is_hostname' ) ) ) );

		if ( ! $hosts ) {
			return false;
		}

		$cache = self::cache();
		$now   = time();
		$due   = array();

		foreach ( $hosts as $host ) {
			if ( $force || ! isset( $cache[ $host ]['checked'] ) || $now - (int) $cache[ $host ]['checked'] >= self::RECHECK ) {
				$due[] = $host;
			}
		}

		if ( ! $due ) {
			return false;
		}

		if ( ! $force ) {
			if ( get_transient( self::LOCK ) ) {
				return false;
			}

			set_transient( self::LOCK, 1, self::RECHECK );
		}

		$changed = false;

		foreach ( $due as $host ) {
			$found = self::lookup( $host );
			$old   = isset( $cache[ $host ]['ips'] ) && is_array( $cache[ $host ]['ips'] ) ? $cache[ $host ]['ips'] : array();
			$entry = isset( $cache[ $host ] ) && is_array( $cache[ $host ] ) ? $cache[ $host ] : array();

			$entry['checked'] = $now;
			$entry['ok']      = '' === $found['error'];
			$entry['error']   = $found['error'];

			if ( $found['ips'] ) {
				$sorted_new = $found['ips'];
				$sorted_old = $old;
				sort( $sorted_new );
				sort( $sorted_old );

				if ( $sorted_new !== $sorted_old ) {
					$entry['changed'] = $now;
					$changed          = true;
				}

				$entry['ips'] = $found['ips'];
			} else {
				// Keep the last good addresses through a failed lookup.
				$entry['ips'] = $old;
			}

			$cache[ $host ] = $entry;
		}

		update_option( self::OPTION, $cache, true );

		return $changed;
	}

	/**
	 * Drop hostnames that are no longer on any list.
	 *
	 * @param string[] $keep Hostnames still in use.
	 * @return void
	 */
	public static function prune( array $keep ) {
		$cache = self::cache();
		$kept  = array_intersect_key( $cache, array_flip( $keep ) );

		if ( count( $kept ) !== count( $cache ) ) {
			update_option( self::OPTION, $kept, true );
		}
	}
}
