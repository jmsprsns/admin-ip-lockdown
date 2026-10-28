<?php
/**
 * Cloudflare's network ranges, so the visitor IP header Cloudflare adds is
 * only believed on requests that really come from Cloudflare.
 *
 * The plugin ships with Cloudflare's published list and refreshes it once a
 * week from Cloudflare's API. A fetched list is only added to the bundled
 * one, never replaces it, and is ignored unless every line is a well-formed
 * range of a sane size.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Cloudflare IP ranges.
 */
final class Admin_IP_Lockdown_Cloudflare {

	/**
	 * Option holding the last list fetched from Cloudflare.
	 */
	const OPTION = 'admin_ip_lockdown_cloudflare';

	/**
	 * Where Cloudflare publishes its ranges.
	 */
	const API = 'https://api.cloudflare.com/client/v4/ips';

	/**
	 * Cloudflare's IPv4 ranges (https://www.cloudflare.com/ips-v4).
	 */
	const V4 = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
	);

	/**
	 * Cloudflare's IPv6 ranges (https://www.cloudflare.com/ips-v6).
	 */
	const V6 = array(
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	/**
	 * Every range, cached per request.
	 *
	 * @var string[]|null
	 */
	private static $ranges = null;

	/**
	 * The bundled ranges plus any fetched ones.
	 *
	 * @return string[]
	 */
	public static function ranges() {
		if ( null !== self::$ranges ) {
			return self::$ranges;
		}

		$ranges  = array_merge( self::V4, self::V6 );
		$fetched = get_option( self::OPTION );

		if ( is_array( $fetched ) && isset( $fetched['ranges'] ) && is_array( $fetched['ranges'] ) ) {
			foreach ( $fetched['ranges'] as $range ) {
				if ( is_string( $range ) && self::valid_range( $range ) ) {
					$ranges[] = $range;
				}
			}
		}

		self::$ranges = array_values( array_unique( $ranges ) );

		return self::$ranges;
	}

	/**
	 * Whether an address belongs to Cloudflare.
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	public static function contains( $ip ) {
		return '' !== $ip && Admin_IP_Lockdown_IP::in_any( $ip, self::ranges() );
	}

	/**
	 * When the list was last fetched.
	 *
	 * @return int Unix time, 0 if never.
	 */
	public static function updated() {
		$fetched = get_option( self::OPTION );

		return is_array( $fetched ) && isset( $fetched['updated'] ) ? (int) $fetched['updated'] : 0;
	}

	/**
	 * A range Cloudflare could plausibly own: well formed and no wider than
	 * /12 (IPv4) or /24 (IPv6). Cloudflare's widest today are /13 and /29.
	 *
	 * @param string $range CIDR.
	 * @return bool
	 */
	private static function valid_range( $range ) {
		$parts = explode( '/', $range, 2 );

		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[1] ) ) {
			return false;
		}

		$ip     = Admin_IP_Lockdown_IP::normalize( $parts[0] );
		$prefix = (int) $parts[1];

		if ( '' === $ip ) {
			return false;
		}

		if ( Admin_IP_Lockdown_IP::is_v6( $ip ) ) {
			return $prefix >= 24 && $prefix <= 128;
		}

		return $prefix >= 12 && $prefix <= 32;
	}

	/**
	 * Fetch the current list from Cloudflare (weekly, by WP-Cron).
	 *
	 * @return bool Whether a valid list was stored.
	 */
	public static function refresh() {
		$response = wp_safe_remote_get(
			self::API,
			array(
				'timeout'     => 10,
				'redirection' => 0,
				'headers'     => array( 'Accept' => 'application/json' ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) || empty( $body['success'] ) || ! isset( $body['result']['ipv4_cidrs'], $body['result']['ipv6_cidrs'] ) ) {
			return false;
		}

		$v4 = is_array( $body['result']['ipv4_cidrs'] ) ? $body['result']['ipv4_cidrs'] : array();
		$v6 = is_array( $body['result']['ipv6_cidrs'] ) ? $body['result']['ipv6_cidrs'] : array();

		// A short, huge or malformed list means something's wrong: keep the old one.
		if ( count( $v4 ) < 5 || count( $v6 ) < 3 || count( $v4 ) + count( $v6 ) > 200 ) {
			return false;
		}

		$ranges = array();

		foreach ( array_merge( $v4, $v6 ) as $range ) {
			if ( ! is_string( $range ) || ! self::valid_range( $range ) ) {
				return false;
			}

			$ranges[] = $range;
		}

		update_option(
			self::OPTION,
			array(
				'ranges'  => $ranges,
				'updated' => time(),
			),
			true
		);

		self::$ranges = null;

		return true;
	}
}
