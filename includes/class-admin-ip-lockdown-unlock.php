<?php
/**
 * Emergency unlock links, so an administrator on a new network can't be
 * locked out of their own site.
 *
 * From the blocked page an administrator enters their account's email
 * address and gets a one-time link. Opening it shows a confirmation button
 * (so email scanners that open links can't use it up), and pressing that
 * gives the network they're on temporary access.
 *
 * - Only accounts that can manage the site get a link. The page answers the
 *   same way whatever address is entered, so it can't be used to find out
 *   who the administrators are.
 * - The link's token is random, stored only as a keyed hash, works once and
 *   runs out after an hour.
 * - Requests are limited per visitor address and per account, so the form
 *   can't be used to flood an inbox.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Unlock links.
 */
final class Admin_IP_Lockdown_Unlock {

	/**
	 * User meta holding the current link's hash and expiry.
	 */
	const META = 'admin_ip_lockdown_unlock';

	/**
	 * User meta holding when links were last sent (for the per-account limit).
	 */
	const SENT_META = 'admin_ip_lockdown_unlock_sent';

	/**
	 * Option holding recent requests per visitor address (hashed).
	 */
	const RATE = 'admin_ip_lockdown_unlock_rate';

	/**
	 * How long a link works.
	 */
	const LINK_TTL = HOUR_IN_SECONDS;

	/**
	 * Requests allowed from one address per window.
	 */
	const PER_IP = 5;

	/**
	 * Length of the per-address window.
	 */
	const IP_WINDOW = 900;

	/**
	 * Links sent to one account per hour.
	 */
	const PER_USER = 3;

	/**
	 * Query arguments in the link.
	 */
	const ARG_TOKEN = 'ailock_unlock';
	const ARG_USER  = 'ailock_user';

	/**
	 * Whether an account may ask for a link: administrators (and super admins).
	 *
	 * @param WP_User $user Account.
	 * @return bool
	 */
	public static function can_request( $user ) {
		if ( ! $user instanceof WP_User || ! $user->exists() ) {
			return false;
		}

		return ( is_multisite() && is_super_admin( $user->ID ) ) || user_can( $user, 'manage_options' );
	}

	/**
	 * Accounts that can ask for a link, for the settings page.
	 *
	 * @return WP_User[]
	 */
	public static function eligible_users() {
		$args = array(
			'number'  => 50,
			'orderby' => 'login',
		);

		// The capability argument arrived in WordPress 5.9; older versions
		// ignore it and would list everyone.
		if ( version_compare( get_bloginfo( 'version' ), '5.9', '>=' ) ) {
			$args['capability'] = 'manage_options';
		} else {
			$args['role'] = 'administrator';
		}

		return array_values( array_filter( get_users( $args ), array( __CLASS__, 'can_request' ) ) );
	}

	/**
	 * Count a request from an address and say whether it's within the limit.
	 *
	 * @param string $ip Address.
	 * @return bool False when this address has asked too often.
	 */
	private static function within_ip_limit( $ip ) {
		$now   = time();
		$key   = substr( hash_hmac( 'sha256', $ip, wp_salt( 'nonce' ) ), 0, 20 );
		$saved = get_option( self::RATE, array() );
		$rates = array();

		foreach ( is_array( $saved ) ? $saved : array() as $hash => $item ) {
			if ( is_array( $item ) && isset( $item[1] ) && $now - (int) $item[1] < self::IP_WINDOW ) {
				$rates[ $hash ] = $item;
			}
		}

		$count = isset( $rates[ $key ] ) ? (int) $rates[ $key ][0] : 0;

		if ( $count >= self::PER_IP ) {
			return false;
		}

		$rates[ $key ] = array( $count + 1, isset( $rates[ $key ] ) ? (int) $rates[ $key ][1] : $now );

		// Bounded, whatever the number of addresses.
		update_option( self::RATE, array_slice( $rates, -300, null, true ), false );

		return true;
	}

	/**
	 * Handle a request for a link from the blocked page.
	 *
	 * @param string $email Address entered.
	 * @param string $ip    Visitor's address.
	 * @return string "limited" when this address has asked too often, else
	 *                "ok" (whether or not an email went out).
	 */
	public static function request( $email, $ip ) {
		if ( ! self::within_ip_limit( $ip ) ) {
			return 'limited';
		}

		$email = sanitize_email( substr( (string) $email, 0, 254 ) );
		$user  = is_email( $email ) ? get_user_by( 'email', $email ) : false;

		if ( ! $user || ! self::can_request( $user ) ) {
			return 'ok';
		}

		// Per-account limit, silent so it says nothing about the account.
		$now  = time();
		$sent = array_filter(
			(array) get_user_meta( $user->ID, self::SENT_META, true ),
			function ( $time ) use ( $now ) {
				return is_numeric( $time ) && $now - (int) $time < HOUR_IN_SECONDS;
			}
		);

		if ( count( $sent ) >= self::PER_USER ) {
			return 'ok';
		}

		$token = self::new_token();

		update_user_meta(
			$user->ID,
			self::META,
			array(
				'hash'    => self::hash( $token ),
				'expires' => $now + self::LINK_TTL,
				'ip'      => $ip,
			)
		);

		$sent[] = $now;
		update_user_meta( $user->ID, self::SENT_META, array_values( $sent ) );

		Admin_IP_Lockdown_Log::event( 'requested', $user->ID, $ip );

		// Sent once the page has gone out, where the server allows it, so the
		// response doesn't take longer for an administrator's address.
		self::$pending = array( $user, $token, $ip );
		register_shutdown_function( array( __CLASS__, 'send_pending' ) );

		return 'ok';
	}

	/**
	 * Link waiting to be emailed at the end of the request.
	 *
	 * @var array|null
	 */
	private static $pending = null;

	/**
	 * Finish the response, then email the waiting link.
	 *
	 * @return void
	 */
	public static function send_pending() {
		if ( null === self::$pending ) {
			return;
		}

		list( $user, $token, $ip ) = self::$pending;
		self::$pending             = null;

		if ( function_exists( 'fastcgi_finish_request' ) ) {
			fastcgi_finish_request();
		} elseif ( function_exists( 'litespeed_finish_request' ) ) {
			litespeed_finish_request();
		}

		self::send_link( $user, $token, $ip );
	}

	/**
	 * A new random token (48 hex characters).
	 *
	 * @return string
	 */
	private static function new_token() {
		try {
			return bin2hex( random_bytes( 24 ) );
		} catch ( Exception $e ) {
			return strtolower( wp_generate_password( 48, false, false ) );
		}
	}

	/**
	 * Keyed hash of a token, which is all that's stored.
	 *
	 * @param string $token Token.
	 * @return string
	 */
	private static function hash( $token ) {
		return hash_hmac( 'sha256', 'admin-ip-lockdown-unlock|' . $token, wp_salt( 'auth' ) );
	}

	/**
	 * The link for a token.
	 *
	 * @param int    $user_id Account.
	 * @param string $token   Token.
	 * @return string
	 */
	public static function link( $user_id, $token ) {
		return add_query_arg(
			array(
				self::ARG_TOKEN => rawurlencode( $token ),
				self::ARG_USER  => (int) $user_id,
			),
			wp_login_url()
		);
	}

	/**
	 * The site name for emails.
	 *
	 * @return string
	 */
	public static function site_name() {
		$name = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );

		return '' !== trim( $name ) ? trim( preg_replace( '/[\r\n]+/', ' ', $name ) ) : (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * A length of time in words ("24 hours", "7 days").
	 *
	 * @param int $hours Hours.
	 * @return string
	 */
	public static function duration( $hours ) {
		$hours = (int) $hours;

		if ( $hours >= 48 && 0 === $hours % 24 ) {
			/* translators: %d: number of days. */
			return sprintf( _n( '%d day', '%d days', $hours / 24, 'admin-ip-lockdown' ), $hours / 24 );
		}

		/* translators: %d: number of hours. */
		return sprintf( _n( '%d hour', '%d hours', $hours, 'admin-ip-lockdown' ), $hours );
	}

	/**
	 * Email the link.
	 *
	 * @param WP_User $user  Account.
	 * @param string  $token Token.
	 * @param string  $ip    Address that asked.
	 * @return bool
	 */
	private static function send_link( WP_User $user, $token, $ip ) {
		$hours = Admin_IP_Lockdown_Plugin::settings()['unlock_hours'];
		$site  = self::site_name();

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] Your link to unlock the admin area', 'admin-ip-lockdown' ), $site );

		$lines = array(
			sprintf(
				/* translators: 1: site name, 2: IP address, 3: date and time. */
				__( 'Someone (hopefully you) asked to unlock the admin area of %1$s from %2$s on %3$s.', 'admin-ip-lockdown' ),
				$site,
				$ip,
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) )
			),
			'',
			__( 'To let in the network you\'re on, open this link within the next hour and press "Unlock access":', 'admin-ip-lockdown' ),
			'',
			self::link( $user->ID, $token ),
			'',
			sprintf(
				/* translators: %s: length of time, e.g. "24 hours". */
				__( 'Access lasts %s for that network. You\'ll still sign in with your password as usual. The link works once.', 'admin-ip-lockdown' ),
				self::duration( $hours )
			),
			'',
			__( 'If you didn\'t ask for this, ignore this email. Nothing changes unless the link is used.', 'admin-ip-lockdown' ),
			'',
			'-- ',
			sprintf(
				/* translators: %s: site address. */
				__( 'Admin IP Lockdown on %s', 'admin-ip-lockdown' ),
				home_url( '/' )
			),
		);

		return wp_mail( $user->user_email, $subject, implode( "\n", $lines ) );
	}

	/**
	 * Whether this request carries an unlock link.
	 *
	 * @return bool
	 */
	public static function link_in_request() {
		return isset( $_GET[ self::ARG_TOKEN ], $_GET[ self::ARG_USER ] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- The token is the credential.
	}

	/**
	 * The account a valid link belongs to.
	 *
	 * @return WP_User|false
	 */
	public static function verify_request() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- The token is the credential.
		$token   = isset( $_GET[ self::ARG_TOKEN ] ) && is_string( $_GET[ self::ARG_TOKEN ] ) ? strtolower( sanitize_text_field( wp_unslash( $_GET[ self::ARG_TOKEN ] ) ) ) : '';
		$user_id = isset( $_GET[ self::ARG_USER ] ) && is_string( $_GET[ self::ARG_USER ] ) ? absint( $_GET[ self::ARG_USER ] ) : 0;
		// phpcs:enable

		if ( ! $user_id || ! preg_match( '/^[a-z0-9]{48}$/', $token ) ) {
			return false;
		}

		$user  = get_userdata( $user_id );
		$saved = $user ? get_user_meta( $user_id, self::META, true ) : null;

		if ( ! $user || ! is_array( $saved ) || empty( $saved['hash'] ) || empty( $saved['expires'] ) ) {
			return false;
		}

		if ( (int) $saved['expires'] < time() || ! hash_equals( (string) $saved['hash'], self::hash( $token ) ) ) {
			return false;
		}

		return self::can_request( $user ) ? $user : false;
	}

	/**
	 * Use a verified link: give the visitor's network access and spend the link.
	 *
	 * @param WP_User $user Account the link belongs to.
	 * @param string  $ip   Visitor's address.
	 * @return array|false The temporary access item.
	 */
	public static function consume( WP_User $user, $ip ) {
		// Spend it first, so a double submit can't use it twice.
		delete_user_meta( $user->ID, self::META );

		$hours = Admin_IP_Lockdown_Plugin::settings()['unlock_hours'];
		$item  = Admin_IP_Lockdown_Access::add_temporary( $ip, $user->ID, $hours * HOUR_IN_SECONDS );

		if ( ! $item ) {
			return false;
		}

		Admin_IP_Lockdown_Log::event( 'used', $user->ID, $item['value'] );

		if ( Admin_IP_Lockdown_Plugin::settings()['notify_unlock'] ) {
			self::notify( $user, $item );
		}

		return $item;
	}

	/**
	 * Tell the site's admin email address that a link was used.
	 *
	 * @param WP_User $user Account that used it.
	 * @param array   $item Temporary access item.
	 * @return void
	 */
	private static function notify( WP_User $user, array $item ) {
		$to = get_option( 'admin_email' );

		if ( ! is_email( $to ) || strtolower( $to ) === strtolower( $user->user_email ) ) {
			return;
		}

		$site = self::site_name();

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] The admin area was unlocked with an email link', 'admin-ip-lockdown' ), $site );

		$lines = array(
			sprintf(
				/* translators: 1: username, 2: IP address or network, 3: date and time. */
				__( '%1$s used an emailed unlock link. %2$s can reach the admin area until %3$s.', 'admin-ip-lockdown' ),
				$user->user_login,
				$item['value'],
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $item['expires'] )
			),
			'',
			__( 'If that wasn\'t expected, remove it under Content Powered > Admin IP Lockdown and change that account\'s password.', 'admin-ip-lockdown' ),
			'',
			admin_url( 'admin.php?page=' . Admin_IP_Lockdown_Admin::PAGE ),
		);

		wp_mail( $to, $subject, implode( "\n", $lines ) );
	}

	/**
	 * Send a test message so you know unlock emails arrive before you need one.
	 *
	 * @param WP_User $user Recipient.
	 * @return bool
	 */
	public static function send_test( WP_User $user ) {
		$site = self::site_name();

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] Admin IP Lockdown test email', 'admin-ip-lockdown' ), $site );

		$lines = array(
			__( 'This is a test from Admin IP Lockdown. Unlock links will arrive like this, at this address.', 'admin-ip-lockdown' ),
			'',
			__( 'If you ever get locked out, use "Email me an unlock link" on the page you see instead of the login screen.', 'admin-ip-lockdown' ),
		);

		Admin_IP_Lockdown_Log::event( 'test', $user->ID, Admin_IP_Lockdown_Request::client_ip() );

		return wp_mail( $user->user_email, $subject, implode( "\n", $lines ) );
	}
}
