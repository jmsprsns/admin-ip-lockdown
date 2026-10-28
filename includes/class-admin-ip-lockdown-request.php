<?php
/**
 * Works out the visitor's real IP address.
 *
 * REMOTE_ADDR is the only value a visitor can't fake. Proxy headers
 * (CF-Connecting-IP, X-Forwarded-For...) are believed only when the request
 * arrives from a proxy that sets them: Cloudflare's own network, or
 * addresses the site owner lists as their own proxies or load balancers.
 * Sent straight to the server, those headers are ignored.
 *
 * Also signs the site's own loopback requests (Site Health, the plugin and
 * theme file editor's safety check), which come from the server's address
 * and would otherwise be locked out like any other.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Request inspection.
 */
final class Admin_IP_Lockdown_Request {

	/**
	 * Headers a custom proxy can pass the visitor's address in: setting value => $_SERVER key.
	 */
	const HEADERS = array(
		'x-forwarded-for'   => 'HTTP_X_FORWARDED_FOR',
		'x-real-ip'         => 'HTTP_X_REAL_IP',
		'true-client-ip'    => 'HTTP_TRUE_CLIENT_IP',
		'x-sucuri-clientip' => 'HTTP_X_SUCURI_CLIENTIP',
	);

	/**
	 * Header carrying the loopback signature.
	 */
	const LOOPBACK_HEADER = 'X-Admin-IP-Lockdown';

	/**
	 * How long a loopback signature lasts, in seconds (the current and the
	 * previous window are accepted).
	 */
	const LOOPBACK_WINDOW = 300;

	/**
	 * Result for the live settings, worked out once per request.
	 *
	 * @var array|null
	 */
	private static $current = null;

	/**
	 * A $_SERVER value as a string.
	 *
	 * @param string $key Key.
	 * @return string
	 */
	public static function server( $key ) {
		if ( ! isset( $_SERVER[ $key ] ) || ! is_string( $_SERVER[ $key ] ) ) {
			return '';
		}

		// Only ever validated as an IP address or compared, never output raw.
		return substr( trim( wp_unslash( $_SERVER[ $key ] ) ), 0, 2048 ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
	}

	/**
	 * The visitor's IP address under the saved settings.
	 *
	 * @return string Empty when it can't be told.
	 */
	public static function client_ip() {
		if ( null === self::$current ) {
			self::$current = self::resolve( Admin_IP_Lockdown_Plugin::settings() );
		}

		return self::$current['ip'];
	}

	/**
	 * Forget the cached result (after the settings change).
	 *
	 * @return void
	 */
	public static function reset() {
		self::$current = null;
	}

	/**
	 * Work out the visitor's address under a given set of settings.
	 *
	 * Starting from REMOTE_ADDR, each hop that's a trusted proxy is replaced
	 * by the address that proxy reports, right to left, so entries a visitor
	 * adds to the left of X-Forwarded-For are never reached. A malformed
	 * entry stops the walk at the proxy, which then counts as the visitor
	 * (and isn't on the allowed list), so bad headers fail closed.
	 *
	 * @param array $settings Plugin settings.
	 * @return array{ip:string,remote:string,via:string,cloudflare:bool}
	 */
	public static function resolve( array $settings ) {
		$remote = Admin_IP_Lockdown_IP::normalize( self::server( 'REMOTE_ADDR' ) );
		$result = array(
			'ip'         => $remote,
			'remote'     => $remote,
			'via'        => 'direct',
			'cloudflare' => false,
		);

		if ( '' === $remote ) {
			return $result;
		}

		$proxies = isset( $settings['proxies'] ) && is_array( $settings['proxies'] ) ? $settings['proxies'] : array();
		$header  = isset( $settings['proxy_header'], self::HEADERS[ $settings['proxy_header'] ] ) ? self::HEADERS[ $settings['proxy_header'] ] : self::HEADERS['x-forwarded-for'];
		$chain   = null;
		$ip      = $remote;

		for ( $hop = 0; $hop < 10; $hop++ ) {
			if ( ! empty( $settings['cloudflare'] ) && Admin_IP_Lockdown_Cloudflare::contains( $ip ) ) {
				$result['cloudflare'] = true;

				// Cloudflare always overwrites CF-Connecting-IP, so it can be trusted.
				// With Pseudo IPv4 set to "Overwrite headers" it holds a made-up
				// address from 240.0.0.0/4 and the real one is in CF-Connecting-IPv6.
				// Only then is that second header read: on other zones a visitor
				// could send it themselves.
				$visitor = Admin_IP_Lockdown_IP::normalize( self::server( 'HTTP_CF_CONNECTING_IP' ) );

				if ( Admin_IP_Lockdown_IP::in_range( $visitor, '240.0.0.0/4' ) ) {
					$visitor = Admin_IP_Lockdown_IP::normalize( self::server( 'HTTP_CF_CONNECTING_IPV6' ) );
				}

				if ( '' !== $visitor ) {
					$ip            = $visitor;
					$result['via'] = 'cloudflare';
				}

				break;
			}

			if ( $proxies && Admin_IP_Lockdown_IP::in_any( $ip, $proxies ) ) {
				if ( null === $chain ) {
					$chain = self::header_chain( $header );
				}

				$next = array_pop( $chain );

				if ( null === $next || '' === $next ) {
					break;
				}

				$ip            = $next;
				$result['via'] = 'proxy';
				continue;
			}

			break;
		}

		$result['ip'] = $ip;

		return $result;
	}

	/**
	 * A forwarding header split into addresses, left to right. Entries that
	 * aren't valid addresses come back as '' so the walk stops there.
	 *
	 * @param string $key $_SERVER key.
	 * @return string[]
	 */
	private static function header_chain( $key ) {
		$raw = self::server( $key );

		if ( '' === $raw ) {
			return array();
		}

		$chain = array();

		foreach ( array_slice( explode( ',', $raw ), -20 ) as $part ) {
			$part = trim( $part );

			// Drop a port, written either way: bracketed IPv6 with a port, or IPv4 with a port.
			if ( preg_match( '/^\[([^\]]+)\](?::\d+)?$/', $part, $match ) || preg_match( '/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $part, $match ) ) {
				$part = $match[1];
			}

			$chain[] = Admin_IP_Lockdown_IP::normalize( $part );
		}

		return $chain;
	}

	/**
	 * Proxy-related headers on this request, for the IP detection tab.
	 *
	 * @return array<string,string> Header name => value (shortened).
	 */
	public static function proxy_headers() {
		$names = array(
			'CF-Connecting-IP'   => 'HTTP_CF_CONNECTING_IP',
			'CF-Connecting-IPv6' => 'HTTP_CF_CONNECTING_IPV6',
			'X-Forwarded-For'    => 'HTTP_X_FORWARDED_FOR',
			'X-Real-IP'          => 'HTTP_X_REAL_IP',
			'True-Client-IP'     => 'HTTP_TRUE_CLIENT_IP',
			'X-Sucuri-ClientIP'  => 'HTTP_X_SUCURI_CLIENTIP',
			'Forwarded'          => 'HTTP_FORWARDED',
		);
		$found = array();

		foreach ( $names as $name => $key ) {
			$value = self::server( $key );

			if ( '' !== $value ) {
				$found[ $name ] = substr( preg_replace( '/[^\x20-\x7e]/', '', $value ), 0, 160 );
			}
		}

		return $found;
	}

	/**
	 * The loopback signature for a time window. Keyed with the site's secret
	 * salt, so only this server can make one.
	 *
	 * @param int $window Window number (time divided by the window length).
	 * @return string
	 */
	private static function loopback_token( $window ) {
		return hash_hmac( 'sha256', 'admin-ip-lockdown-loopback|' . (int) $window, wp_salt( 'auth' ) );
	}

	/**
	 * Whether this request is one of the site's own, signed loopback requests.
	 *
	 * @return bool
	 */
	public static function is_signed_loopback() {
		$sent = self::server( 'HTTP_X_ADMIN_IP_LOCKDOWN' );

		if ( 64 !== strlen( $sent ) || ! function_exists( 'wp_salt' ) ) {
			return false;
		}

		$window = (int) floor( time() / self::LOOPBACK_WINDOW );

		return hash_equals( self::loopback_token( $window ), $sent ) || hash_equals( self::loopback_token( $window - 1 ), $sent );
	}

	/**
	 * Sign requests an administrator's page load makes back to this same
	 * site (Site Health, the file editor's check for fatal errors), so they
	 * get through from the server's own address. Requests to any other host
	 * never carry the signature.
	 *
	 * @param array  $args Request arguments.
	 * @param string $url  Request URL.
	 * @return array
	 */
	public static function sign_loopback( $args, $url ) {
		if ( ! is_array( $args ) || ! is_string( $url ) || ! function_exists( 'wp_get_current_user' ) || ! current_user_can( 'manage_options' ) ) {
			return $args;
		}

		$host = wp_parse_url( $url, PHP_URL_HOST );

		if ( ! is_string( $host ) || '' === $host ) {
			return $args;
		}

		$own = array(
			wp_parse_url( home_url(), PHP_URL_HOST ),
			wp_parse_url( site_url(), PHP_URL_HOST ),
		);

		if ( ! in_array( strtolower( $host ), array_map( 'strtolower', array_filter( $own, 'is_string' ) ), true ) ) {
			return $args;
		}

		if ( ! isset( $args['headers'] ) ) {
			$args['headers'] = array();
		}

		// Headers passed as a raw string are left alone rather than rebuilt.
		if ( ! is_array( $args['headers'] ) ) {
			return $args;
		}

		$args['headers'][ self::LOOPBACK_HEADER ] = self::loopback_token( (int) floor( time() / self::LOOPBACK_WINDOW ) );

		return $args;
	}
}
