<?php
/**
 * Main plugin orchestrator: owns the settings and boots the admin side.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Main plugin singleton.
 */
final class Admin_IP_Lockdown_Plugin {

	/**
	 * Option key holding the plugin's settings array.
	 */
	const OPTION = 'admin_ip_lockdown_settings';

	/**
	 * Daily clean-up: old log rows and expired temporary access.
	 */
	const CRON_DAILY = 'admin_ip_lockdown_daily';

	/**
	 * Weekly refresh of Cloudflare's address list.
	 */
	const CRON_CLOUDFLARE = 'admin_ip_lockdown_cloudflare_refresh';

	/**
	 * Most entries on the allowed list.
	 */
	const MAX_ENTRIES = 200;

	/**
	 * Most hostnames on the allowed list (each one is a DNS lookup).
	 */
	const MAX_HOSTS = 10;

	/**
	 * Most trusted proxy addresses or ranges.
	 */
	const MAX_PROXIES = 50;

	/**
	 * How long an unlock link's access can last, in hours.
	 */
	const UNLOCK_HOURS = array( 1, 4, 12, 24, 72, 168 );

	/**
	 * Who counts as staff: the capability that makes an account one.
	 */
	const STAFF = array( 'edit_posts', 'manage_options' );

	/**
	 * Single shared instance.
	 *
	 * @var Admin_IP_Lockdown_Plugin|null
	 */
	private static $instance = null;

	/**
	 * Settings with defaults filled in, cached for the request.
	 *
	 * @var array|null
	 */
	private static $settings = null;

	/**
	 * Get (and lazily create) the shared instance.
	 *
	 * @return Admin_IP_Lockdown_Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Wire everything up.
	 */
	private function __construct() {
		if ( is_admin() ) {
			new Admin_IP_Lockdown_Admin( $this );
		}

		add_action( self::CRON_DAILY, array( __CLASS__, 'daily' ) );
		add_action( self::CRON_CLOUDFLARE, array( 'Admin_IP_Lockdown_Cloudflare', 'refresh' ) );
		add_action( 'admin_init', array( __CLASS__, 'upgrade' ) );

		add_action( 'add_option_' . self::OPTION, array( __CLASS__, 'flush' ) );
		add_action( 'update_option_' . self::OPTION, array( __CLASS__, 'flush' ) );
		add_action( 'update_option_' . Admin_IP_Lockdown_Access::TEMPORARY, array( __CLASS__, 'flush' ) );
	}

	/**
	 * Default value for every setting.
	 *
	 * @return array<string,mixed>
	 */
	public static function defaults() {
		return array(
			'enabled'        => 0,
			'entries'        => array(),
			'protect_admin'  => 1,
			'protect_login'  => 1,
			'protect_xmlrpc' => 0,
			'staff'          => 'edit_posts',
			'login_guard'    => 1,
			'session_guard'  => 1,
			'app_passwords'  => 1,
			'unlock_email'   => 1,
			'unlock_hours'   => 24,
			'notify_unlock'  => 1,
			'message'        => '',
			'cloudflare'     => 1,
			'proxies'        => array(),
			'proxy_header'   => 'x-forwarded-for',
			'log'            => 1,
		);
	}

	/**
	 * All settings, with defaults filled in and every value checked, so the
	 * guard can trust what it reads even if the option was edited by hand.
	 *
	 * @return array<string,mixed>
	 */
	public static function settings() {
		if ( null === self::$settings ) {
			$saved          = get_option( self::OPTION, array() );
			self::$settings = self::normalize( is_array( $saved ) ? $saved : array() );
		}

		return self::$settings;
	}

	/**
	 * Fill in defaults and drop anything malformed.
	 *
	 * @param array $saved Stored settings.
	 * @return array<string,mixed>
	 */
	public static function normalize( array $saved ) {
		$settings = wp_parse_args( $saved, self::defaults() );
		$entries  = array();

		foreach ( is_array( $settings['entries'] ) ? $settings['entries'] : array() as $entry ) {
			if ( is_array( $entry ) && isset( $entry['type'], $entry['value'] ) && in_array( $entry['type'], array( 'ip', 'range', 'host' ), true ) && is_string( $entry['value'] ) && '' !== $entry['value'] ) {
				$entries[] = array(
					'type'  => $entry['type'],
					'value' => $entry['value'],
					'label' => isset( $entry['label'] ) && is_string( $entry['label'] ) ? $entry['label'] : '',
					'added' => isset( $entry['added'] ) ? (int) $entry['added'] : 0,
				);
			}
		}

		$settings['entries'] = array_slice( $entries, 0, self::MAX_ENTRIES );
		$settings['proxies'] = array_values( array_filter( is_array( $settings['proxies'] ) ? $settings['proxies'] : array(), 'is_string' ) );

		foreach ( array( 'enabled', 'protect_admin', 'protect_login', 'protect_xmlrpc', 'login_guard', 'session_guard', 'app_passwords', 'unlock_email', 'notify_unlock', 'cloudflare', 'log' ) as $key ) {
			$settings[ $key ] = empty( $settings[ $key ] ) ? 0 : 1;
		}

		if ( ! in_array( $settings['staff'], self::STAFF, true ) ) {
			$settings['staff'] = 'edit_posts';
		}

		if ( ! in_array( (int) $settings['unlock_hours'], self::UNLOCK_HOURS, true ) ) {
			$settings['unlock_hours'] = 24;
		}

		$settings['unlock_hours'] = (int) $settings['unlock_hours'];

		if ( ! isset( Admin_IP_Lockdown_Request::HEADERS[ $settings['proxy_header'] ] ) ) {
			$settings['proxy_header'] = 'x-forwarded-for';
		}

		$settings['message'] = is_string( $settings['message'] ) ? $settings['message'] : '';

		return $settings;
	}

	/**
	 * A single setting.
	 *
	 * @param string $key Setting key from {@see defaults()}.
	 * @return mixed Null for an unknown key.
	 */
	public function get_setting( $key ) {
		$settings = self::settings();

		return isset( $settings[ $key ] ) ? $settings[ $key ] : null;
	}

	/**
	 * Forget cached settings and decisions after anything changes.
	 *
	 * @return void
	 */
	public static function flush() {
		self::$settings = null;
		Admin_IP_Lockdown_Request::reset();
		Admin_IP_Lockdown_Access::reset();
	}

	/**
	 * Whether ADMIN_IP_LOCKDOWN_DISABLE in wp-config.php has switched the
	 * lockdown off: the way back in with only file access.
	 *
	 * @return bool
	 */
	public static function disabled_by_constant() {
		return defined( 'ADMIN_IP_LOCKDOWN_DISABLE' ) && ADMIN_IP_LOCKDOWN_DISABLE;
	}

	/**
	 * Whether the lockdown is switched on and able to run.
	 *
	 * @return bool
	 */
	public static function enforcing() {
		$settings = self::settings();

		return $settings['enabled']
			&& ! self::disabled_by_constant()
			&& Admin_IP_Lockdown_IP::supported()
			&& Admin_IP_Lockdown_Access::has_entries( $settings );
	}

	/**
	 * Whether an account counts as staff, which limits where it can sign in
	 * and use its session from.
	 *
	 * Reads the account's own capabilities rather than calling user_can(),
	 * because this runs while WordPress is still working out who is signed
	 * in, and other plugins' capability filters may ask that same question.
	 *
	 * @param WP_User $user Account.
	 * @return bool
	 */
	public static function is_staff( $user ) {
		if ( ! $user instanceof WP_User || ! $user->exists() ) {
			return false;
		}

		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			return true;
		}

		$cap = self::settings()['staff'];

		return ! empty( $user->allcaps[ $cap ] ) || ! empty( $user->allcaps['manage_options'] );
	}

	/**
	 * Set up on activation. The lockdown stays off; the activating admin's
	 * own address goes on the list so switching it on is one click.
	 *
	 * @return void
	 */
	public static function activate() {
		Admin_IP_Lockdown_Log::install();

		if ( false === get_option( self::OPTION, false ) ) {
			$settings = self::defaults();
			$ip       = Admin_IP_Lockdown_Request::resolve( $settings )['ip'];

			if ( Admin_IP_Lockdown_IP::is_public( $ip ) ) {
				$settings['entries'][] = array(
					'type'  => Admin_IP_Lockdown_IP::is_v6( $ip ) ? 'range' : 'ip',
					'value' => Admin_IP_Lockdown_IP::is_v6( $ip ) ? Admin_IP_Lockdown_IP::network64( $ip ) : $ip,
					'label' => __( 'Added when the plugin was activated', 'admin-ip-lockdown' ),
					'added' => time(),
				);
			}

			add_option( self::OPTION, $settings );
		}

		self::schedule();
	}

	/**
	 * Make sure the database table and scheduled jobs exist after an update
	 * (updates don't run the activation hook).
	 *
	 * @return void
	 */
	public static function upgrade() {
		Admin_IP_Lockdown_Log::maybe_install();
		self::schedule();
	}

	/**
	 * Schedule the daily clean-up and the weekly Cloudflare refresh.
	 *
	 * @return void
	 */
	public static function schedule() {
		if ( ! wp_next_scheduled( self::CRON_DAILY ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_DAILY );
		}

		if ( ! wp_next_scheduled( self::CRON_CLOUDFLARE ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'weekly', self::CRON_CLOUDFLARE );
		}
	}

	/**
	 * Daily clean-up.
	 *
	 * @return void
	 */
	public static function daily() {
		Admin_IP_Lockdown_Log::prune();
		Admin_IP_Lockdown_Access::prune_temporary();
	}
}
