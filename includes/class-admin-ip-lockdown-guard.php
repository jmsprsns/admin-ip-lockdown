<?php
/**
 * Enforcement: where the lockdown actually stops people.
 *
 * - wp-login.php: blocked for addresses not on the list, except the
 *   actions visitors need (password-protected posts, logging out,
 *   confirming a privacy request).
 * - wp-admin: blocked the same way. admin-ajax.php and admin-post.php stay
 *   open, because front-end features (forms, carts, search) use them.
 * - xmlrpc.php: optional.
 * - Staff sign-ins anywhere else (a shop's account page, XML-RPC, custom
 *   login forms) are refused from other addresses, with the same answer
 *   whether or not the password was right.
 * - Staff sessions only count from allowed addresses, so a stolen login
 *   cookie is useless elsewhere. Application passwords can be exempted, for
 *   apps and integrations.
 *
 * Never applies to WP-CLI, WP-Cron or the site's own signed loopback
 * requests. Doesn't run at all while the lockdown is off, while
 * ADMIN_IP_LOCKDOWN_DISABLE is set in wp-config.php, or with nothing on any
 * list.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * The lockdown.
 */
final class Admin_IP_Lockdown_Guard {

	/**
	 * Actions of wp-login.php that stay open to everyone.
	 */
	const OPEN_LOGIN_ACTIONS = array( 'postpass', 'logout', 'confirmaction' );

	/**
	 * Account that signed in with an application password during this request.
	 *
	 * @var int
	 */
	private static $app_password_user = 0;

	/**
	 * Set while a session is being checked, so a capability filter in another
	 * plugin that asks who's signed in can't loop back into the check.
	 *
	 * @var bool
	 */
	private static $checking = false;

	/**
	 * Hook in.
	 *
	 * @return void
	 */
	public static function init() {
		add_filter( 'determine_current_user', array( __CLASS__, 'filter_current_user' ), 9999 );
		add_action( 'application_password_did_authenticate', array( __CLASS__, 'note_app_password' ) );
		add_filter( 'authenticate', array( __CLASS__, 'filter_authenticate' ), 9999, 2 );
		add_action( 'init', array( __CLASS__, 'check_request' ), 0 );
		add_action( 'login_init', array( __CLASS__, 'check_login_page' ), 0 );
		add_filter( 'http_request_args', array( 'Admin_IP_Lockdown_Request', 'sign_loopback' ), 10, 2 );
	}

	/**
	 * Requests the lockdown never applies to.
	 *
	 * @return bool
	 */
	private static function exempt() {
		return ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || Admin_IP_Lockdown_Request::is_signed_loopback();
	}

	/**
	 * Remember an application password sign-in.
	 *
	 * @param WP_User $user Account.
	 * @return void
	 */
	public static function note_app_password( $user ) {
		if ( $user instanceof WP_User ) {
			self::$app_password_user = (int) $user->ID;
		}
	}

	/**
	 * Whether an account is let through because it used an application password.
	 *
	 * @param int $user_id Account.
	 * @return bool
	 */
	private static function app_password_ok( $user_id ) {
		return Admin_IP_Lockdown_Plugin::settings()['app_passwords'] && self::$app_password_user && self::$app_password_user === (int) $user_id;
	}

	/**
	 * Whether a signed-in account should be treated as signed out here.
	 *
	 * @param WP_User|false $user Account.
	 * @return bool
	 */
	private static function should_block_user( $user ) {
		if ( ! Admin_IP_Lockdown_Plugin::is_staff( $user ) || self::app_password_ok( $user->ID ) ) {
			return false;
		}

		return ! Admin_IP_Lockdown_Access::is_allowed( Admin_IP_Lockdown_Request::client_ip() );
	}

	/**
	 * Staff sessions only count from allowed addresses.
	 *
	 * @param int|false $user_id Account WordPress found, if any.
	 * @return int|false
	 */
	public static function filter_current_user( $user_id ) {
		if ( ! $user_id || self::$checking || self::exempt() ) {
			return $user_id;
		}

		if ( ! Admin_IP_Lockdown_Plugin::settings()['session_guard'] || ! Admin_IP_Lockdown_Plugin::enforcing() ) {
			return $user_id;
		}

		self::$checking = true;
		$block          = self::should_block_user( get_userdata( (int) $user_id ) );
		self::$checking = false;

		if ( $block ) {
			Admin_IP_Lockdown_Log::record( Admin_IP_Lockdown_Request::client_ip(), 'session' );

			return 0;
		}

		return $user_id;
	}

	/**
	 * Staff can only sign in from allowed addresses, through any login form.
	 *
	 * Runs after WordPress has checked the password, and answers the same
	 * whether it was right or wrong, so it can't be used to test passwords.
	 *
	 * @param WP_User|WP_Error|null $user     Result so far.
	 * @param string                $username Username or email entered.
	 * @return WP_User|WP_Error|null
	 */
	public static function filter_authenticate( $user, $username ) {
		if ( self::exempt() || ! Admin_IP_Lockdown_Plugin::settings()['login_guard'] || ! Admin_IP_Lockdown_Plugin::enforcing() ) {
			return $user;
		}

		$account = $user instanceof WP_User ? $user : self::find_user( $username );

		if ( ! $account || ! Admin_IP_Lockdown_Plugin::is_staff( $account ) || self::app_password_ok( $account->ID ) ) {
			return $user;
		}

		$ip = Admin_IP_Lockdown_Request::client_ip();

		if ( Admin_IP_Lockdown_Access::is_allowed( $ip ) ) {
			return $user;
		}

		Admin_IP_Lockdown_Log::record( $ip, 'signin' );

		return new WP_Error(
			'admin_ip_lockdown',
			'<strong>' . esc_html__( 'Error:', 'admin-ip-lockdown' ) . '</strong> ' . esc_html__( 'This account can only sign in from approved networks.', 'admin-ip-lockdown' )
		);
	}

	/**
	 * The account a username or email address belongs to.
	 *
	 * @param mixed $username Entered value.
	 * @return WP_User|false
	 */
	private static function find_user( $username ) {
		if ( ! is_string( $username ) || '' === $username ) {
			return false;
		}

		$user = get_user_by( 'login', $username );

		if ( ! $user && is_email( $username ) ) {
			$user = get_user_by( 'email', $username );
		}

		return $user;
	}

	/**
	 * Check wp-admin and xmlrpc.php requests, and sessions another plugin
	 * set up without going through WordPress's usual sign-in check.
	 *
	 * @return void
	 */
	public static function check_request() {
		if ( self::exempt() || ! Admin_IP_Lockdown_Plugin::enforcing() ) {
			return;
		}

		$settings = Admin_IP_Lockdown_Plugin::settings();
		$ip       = Admin_IP_Lockdown_Request::client_ip();

		if ( $settings['session_guard'] && is_user_logged_in() && self::should_block_user( wp_get_current_user() ) ) {
			Admin_IP_Lockdown_Log::record( $ip, 'session' );
			wp_set_current_user( 0 );
		}

		if ( $settings['protect_xmlrpc'] && defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && ! Admin_IP_Lockdown_Access::is_allowed( $ip ) ) {
			Admin_IP_Lockdown_Log::record( $ip, 'xmlrpc' );

			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo esc_html__( 'XML-RPC is restricted to approved networks on this site.', 'admin-ip-lockdown' );
			exit;
		}

		if ( $settings['protect_admin'] && is_admin() && ! wp_doing_ajax() && ! self::is_admin_post() && ! Admin_IP_Lockdown_Access::is_allowed( $ip ) ) {
			Admin_IP_Lockdown_Log::record( $ip, 'admin' );
			Admin_IP_Lockdown_Blocked::render( $ip );
		}
	}

	/**
	 * Whether this is wp-admin/admin-post.php, which front-end forms post to.
	 *
	 * @return bool
	 */
	private static function is_admin_post() {
		return isset( $GLOBALS['pagenow'] ) && 'admin-post.php' === $GLOBALS['pagenow'];
	}

	/**
	 * The wp-login.php action, worked out exactly the way wp-login.php does.
	 * Not sanitized on purpose: it's only compared, character for character,
	 * with the open actions, and any cleaning (say, lowercasing) could make
	 * an action wp-login.php treats as "login" look like an open one.
	 *
	 * @return string
	 */
	private static function login_action() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Compared exactly with a fixed list, as wp-login.php routes it.
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? wp_unslash( $_REQUEST['action'] ) : 'login';

		if ( isset( $_GET['key'] ) ) {
			$action = 'resetpass';
		}

		if ( isset( $_GET['checkemail'] ) ) {
			$action = 'checkemail';
		}
		// phpcs:enable

		return $action;
	}

	/**
	 * Check wp-login.php, and handle unlock links (which arrive there).
	 *
	 * @return void
	 */
	public static function check_login_page() {
		if ( Admin_IP_Lockdown_Unlock::link_in_request() ) {
			self::handle_unlock_link();
			return;
		}

		if ( self::exempt() || ! Admin_IP_Lockdown_Plugin::settings()['protect_login'] || ! Admin_IP_Lockdown_Plugin::enforcing() ) {
			return;
		}

		if ( in_array( self::login_action(), self::OPEN_LOGIN_ACTIONS, true ) ) {
			return;
		}

		$ip = Admin_IP_Lockdown_Request::client_ip();

		if ( Admin_IP_Lockdown_Access::is_allowed( $ip ) ) {
			return;
		}

		Admin_IP_Lockdown_Log::record( $ip, 'login' );
		Admin_IP_Lockdown_Blocked::render( $ip );
	}

	/**
	 * An unlock link: confirm, then give the visitor's network access.
	 *
	 * @return void
	 */
	private static function handle_unlock_link() {
		$ip   = Admin_IP_Lockdown_Request::client_ip();
		$user = Admin_IP_Lockdown_Unlock::verify_request();

		if ( ! $user || '' === $ip ) {
			Admin_IP_Lockdown_Blocked::render_unlock( 'invalid', $ip );
		}

		if ( ! Admin_IP_Lockdown_Plugin::enforcing() || Admin_IP_Lockdown_Access::is_allowed( $ip ) ) {
			Admin_IP_Lockdown_Blocked::render_unlock( 'already', $ip );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- The link's single-use token is the credential.
		if ( 'POST' === Admin_IP_Lockdown_Request::server( 'REQUEST_METHOD' ) && isset( $_POST['ailock_confirm'] ) ) {
			if ( ! Admin_IP_Lockdown_Unlock::consume( $user, $ip ) ) {
				Admin_IP_Lockdown_Blocked::render_unlock( 'invalid', $ip );
			}

			wp_safe_redirect( admin_url() );
			exit;
		}

		$shown = Admin_IP_Lockdown_IP::is_v6( $ip ) ? Admin_IP_Lockdown_IP::network64( $ip ) : $ip;

		Admin_IP_Lockdown_Blocked::render_unlock( 'confirm', $shown, Admin_IP_Lockdown_Unlock::duration( Admin_IP_Lockdown_Plugin::settings()['unlock_hours'] ) );
	}
}
