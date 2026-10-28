<?php
/**
 * IP address helpers: validating, normalising and matching addresses,
 * ranges and hostnames.
 *
 * Everything is compared as binary (inet_pton), so IPv6 addresses written
 * in different ways ("2001:db8::1" and "2001:0db8:0:0::1") match, and an
 * IPv4 address that arrives IPv4-mapped ("::ffff:203.0.113.5") is treated as
 * the plain IPv4 address.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Static IP utilities.
 */
final class Admin_IP_Lockdown_IP {

	/**
	 * Narrowest allowed range prefix for IPv4. Anything wider covers a
	 * large share of the internet and defeats the lockdown.
	 */
	const MIN_PREFIX_V4 = 8;

	/**
	 * Narrowest allowed range prefix for IPv6.
	 */
	const MIN_PREFIX_V6 = 16;

	/**
	 * Parsed ranges, keyed by the range string.
	 *
	 * @var array<string,array|false>
	 */
	private static $ranges = array();

	/**
	 * Whether this PHP can compare addresses at all. inet_pton() is missing
	 * only from PHP builds without IPv6 support; the lockdown won't switch on
	 * there rather than block everyone.
	 *
	 * @return bool
	 */
	public static function supported() {
		return function_exists( 'inet_pton' ) && function_exists( 'inet_ntop' );
	}

	/**
	 * A valid IP address in its shortest standard form, or '' when the input
	 * isn't one. IPv4-mapped IPv6 addresses come back as plain IPv4.
	 *
	 * @param mixed $ip Candidate address.
	 * @return string
	 */
	public static function normalize( $ip ) {
		if ( ! is_string( $ip ) || ! self::supported() ) {
			return '';
		}

		$ip = trim( $ip );

		// "[2001:db8::1]" as written in URLs and some proxy headers.
		if ( '' !== $ip && '[' === $ip[0] && ']' === substr( $ip, -1 ) ) {
			$ip = substr( $ip, 1, -1 );
		}

		// Zone IDs ("fe80::1%eth0") never identify a remote visitor.
		if ( '' === $ip || strlen( $ip ) > 45 || false !== strpos( $ip, '%' ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}

		$binary = inet_pton( $ip );

		if ( false === $binary ) {
			return '';
		}

		// ::ffff:a.b.c.d is an IPv4 address carried over IPv6.
		if ( 16 === strlen( $binary ) && 0 === strncmp( $binary, str_repeat( "\0", 10 ) . "\xff\xff", 12 ) ) {
			$binary = substr( $binary, 12 );
		}

		$text = inet_ntop( $binary );

		return false === $text ? '' : $text;
	}

	/**
	 * Whether a (normalised) address is IPv6.
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	public static function is_v6( $ip ) {
		return false !== strpos( (string) $ip, ':' );
	}

	/**
	 * Whether an address is on the public internet (not private, loopback,
	 * link-local or reserved).
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	public static function is_public( $ip ) {
		$ip = self::normalize( $ip );

		return '' !== $ip && false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Whether an address is the machine itself (127.0.0.0/8 or ::1).
	 *
	 * @param string $ip Address.
	 * @return bool
	 */
	public static function is_loopback( $ip ) {
		$ip = self::normalize( $ip );

		return '::1' === $ip || self::in_range( $ip, '127.0.0.0/8' );
	}

	/**
	 * The /64 network an IPv6 address belongs to, e.g. "2001:db8:1:2::/64".
	 * Every device on a home or mobile connection gets its own address in
	 * the same /64, and most change theirs daily, so a single IPv6 address is
	 * rarely what you want to allow.
	 *
	 * @param string $ip IPv6 address.
	 * @return string Empty for anything that isn't IPv6.
	 */
	public static function network64( $ip ) {
		$ip = self::normalize( $ip );

		if ( '' === $ip || ! self::is_v6( $ip ) ) {
			return '';
		}

		return self::canonical_range( $ip, 64 );
	}

	/**
	 * A range with its host bits cleared, e.g. 203.0.113.77/24 -> 203.0.113.0/24.
	 *
	 * @param string $ip     Address in the range.
	 * @param int    $prefix Prefix length.
	 * @return string Empty when the input is invalid.
	 */
	public static function canonical_range( $ip, $prefix ) {
		$ip = self::normalize( $ip );

		if ( '' === $ip ) {
			return '';
		}

		$binary = inet_pton( $ip );
		$max    = strlen( $binary ) * 8;
		$prefix = (int) $prefix;

		if ( $prefix < 0 || $prefix > $max ) {
			return '';
		}

		$masked = '';

		for ( $i = 0, $len = strlen( $binary ); $i < $len; $i++ ) {
			$bits = max( 0, min( 8, $prefix - $i * 8 ) );
			$mask = $bits ? ( 0xff << ( 8 - $bits ) ) & 0xff : 0;

			$masked .= chr( ord( $binary[ $i ] ) & $mask );
		}

		return inet_ntop( $masked ) . '/' . $prefix;
	}

	/**
	 * Parse a range ("203.0.113.0/24", "2001:db8::/48") into binary network
	 * and prefix. Cached per request.
	 *
	 * @param string $range CIDR range.
	 * @return array{0:string,1:int}|false
	 */
	private static function parse_range( $range ) {
		if ( isset( self::$ranges[ $range ] ) ) {
			return self::$ranges[ $range ];
		}

		$parsed = false;
		$parts  = explode( '/', (string) $range, 2 );

		if ( 2 === count( $parts ) && ctype_digit( $parts[1] ) ) {
			$network = self::normalize( $parts[0] );
			$prefix  = (int) $parts[1];

			if ( '' !== $network ) {
				$binary = inet_pton( $network );

				if ( $prefix <= strlen( $binary ) * 8 ) {
					$parsed = array( $binary, $prefix );
				}
			}
		}

		if ( count( self::$ranges ) < 500 ) {
			self::$ranges[ $range ] = $parsed;
		}

		return $parsed;
	}

	/**
	 * Whether an address falls inside a CIDR range (or equals a single
	 * address, when $range has no prefix).
	 *
	 * @param string $ip    Address.
	 * @param string $range Range or single address.
	 * @return bool
	 */
	public static function in_range( $ip, $range ) {
		$ip = self::normalize( $ip );

		if ( '' === $ip ) {
			return false;
		}

		if ( false === strpos( (string) $range, '/' ) ) {
			return self::normalize( $range ) === $ip;
		}

		$parsed = self::parse_range( $range );

		if ( false === $parsed ) {
			return false;
		}

		list( $network, $prefix ) = $parsed;

		$binary = inet_pton( $ip );

		if ( strlen( $binary ) !== strlen( $network ) ) {
			return false;
		}

		$bytes = intdiv( $prefix, 8 );
		$rest  = $prefix % 8;

		if ( $bytes && substr( $binary, 0, $bytes ) !== substr( $network, 0, $bytes ) ) {
			return false;
		}

		if ( 0 === $rest ) {
			return true;
		}

		$mask = ( 0xff << ( 8 - $rest ) ) & 0xff;

		return ( ord( $binary[ $bytes ] ) & $mask ) === ( ord( $network[ $bytes ] ) & $mask );
	}

	/**
	 * Whether an address is in any of several ranges or addresses.
	 *
	 * @param string   $ip     Address.
	 * @param string[] $ranges Ranges or single addresses.
	 * @return bool
	 */
	public static function in_any( $ip, array $ranges ) {
		foreach ( $ranges as $range ) {
			if ( self::in_range( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether text is a hostname (letters, digits and hyphens in dot-separated
	 * labels, with a top-level label that isn't all digits).
	 *
	 * @param string $host Lowercase candidate.
	 * @return bool
	 */
	public static function is_hostname( $host ) {
		if ( ! is_string( $host ) || strlen( $host ) > 253 || false === strpos( $host, '.' ) ) {
			return false;
		}

		if ( ! preg_match( '/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $host ) ) {
			return false;
		}

		$labels = explode( '.', $host );

		return ! ctype_digit( end( $labels ) );
	}

	/**
	 * Turn what someone typed into an allowed-list entry.
	 *
	 * Accepts an IPv4 or IPv6 address, a CIDR range, an IPv4 wildcard
	 * ("203.0.113.*", "198.51.*") or a hostname. A pasted URL is reduced to
	 * its host.
	 *
	 * @param string $raw Input.
	 * @return array{type:string,value:string}|WP_Error type is ip, range or host.
	 */
	public static function parse_entry( $raw ) {
		$text = strtolower( trim( wp_strip_all_tags( (string) $raw ) ) );

		if ( '' === $text ) {
			return new WP_Error( 'empty', __( 'Empty entry.', 'admin-ip-lockdown' ) );
		}

		if ( strlen( $text ) > 255 ) {
			return new WP_Error( 'long', __( 'That entry is too long.', 'admin-ip-lockdown' ) );
		}

		// A pasted URL: keep the host.
		if ( preg_match( '#^[a-z][a-z0-9+.-]*://#', $text ) ) {
			$host = wp_parse_url( $text, PHP_URL_HOST );
			$text = is_string( $host ) ? trim( $host, '[]' ) : '';
		}

		// IPv4 wildcard: 203.0.113.* -> 203.0.113.0/24.
		if ( preg_match( '/^(\d{1,3}(?:\.\d{1,3}){0,2})(?:\.\*)+$/', $text, $match ) ) {
			$known  = explode( '.', $match[1] );
			$prefix = count( $known ) * 8;
			$ip     = implode( '.', array_pad( $known, 4, '0' ) );

			$text = $ip . '/' . $prefix;
		}

		if ( false !== strpos( $text, '/' ) ) {
			list( $ip, $prefix ) = explode( '/', $text, 2 );

			$ip = self::normalize( $ip );

			if ( '' === $ip || ! ctype_digit( $prefix ) ) {
				return new WP_Error( 'range', __( 'Not a valid range. Write it like 203.0.113.0/24.', 'admin-ip-lockdown' ) );
			}

			$prefix = (int) $prefix;
			$max    = self::is_v6( $ip ) ? 128 : 32;
			$min    = self::is_v6( $ip ) ? self::MIN_PREFIX_V6 : self::MIN_PREFIX_V4;

			if ( $prefix > $max ) {
				return new WP_Error( 'range', __( 'Not a valid range. Write it like 203.0.113.0/24.', 'admin-ip-lockdown' ) );
			}

			if ( $prefix < $min ) {
				return new WP_Error(
					'broad',
					/* translators: %d: smallest allowed prefix length, e.g. 8. */
					sprintf( __( 'That range is too broad: it would let in a large part of the internet. Use /%d or narrower.', 'admin-ip-lockdown' ), $min )
				);
			}

			if ( $prefix === $max ) {
				return array(
					'type'  => 'ip',
					'value' => $ip,
				);
			}

			return array(
				'type'  => 'range',
				'value' => self::canonical_range( $ip, $prefix ),
			);
		}

		$ip = self::normalize( $text );

		if ( '' !== $ip ) {
			return array(
				'type'  => 'ip',
				'value' => $ip,
			);
		}

		// Hostname, without a port or trailing dot.
		$host = rtrim( preg_replace( '/:\d+$/', '', $text ), '.' );

		if ( function_exists( 'idn_to_ascii' ) && preg_match( '/[^\x20-\x7e]/', $host ) ) {
			$ascii = defined( 'INTL_IDNA_VARIANT_UTS46' ) ? idn_to_ascii( $host, 0, INTL_IDNA_VARIANT_UTS46 ) : false;
			$host  = is_string( $ascii ) ? strtolower( $ascii ) : $host;
		}

		if ( self::is_hostname( $host ) ) {
			return array(
				'type'  => 'host',
				'value' => $host,
			);
		}

		return new WP_Error( 'invalid', __( 'Not an IP address, range or hostname.', 'admin-ip-lockdown' ) );
	}

	/**
	 * Whether an address matches a hostname's resolved addresses. IPv6
	 * results cover their whole /64, because each device at home gets its own
	 * IPv6 address while dynamic DNS records only the router's.
	 *
	 * @param string   $ip  Address.
	 * @param string[] $ips Addresses the hostname resolved to.
	 * @return bool
	 */
	public static function matches_resolved( $ip, array $ips ) {
		foreach ( $ips as $resolved ) {
			$range = self::is_v6( $resolved ) ? self::network64( $resolved ) : $resolved;

			if ( '' !== $range && self::in_range( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}
}
