<?php
/**
 * Activity: blocked attempts and unlock-link events.
 *
 * Blocked attempts go in one small table with a row per address per day
 * (attempts are counted, not stored one by one), so a flood of login
 * attempts costs one quick update each and the table stays small. Rows are
 * kept for 30 days. Only the path is stored, never the query string, which
 * can hold reset keys and tokens.
 *
 * Unlock-link events (requested, used, removed) are rare and kept in an option.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Activity log.
 */
final class Admin_IP_Lockdown_Log {

	/**
	 * Table schema version.
	 */
	const DB_VERSION = '1';

	/**
	 * Option recording the installed schema version.
	 */
	const DB_OPTION = 'admin_ip_lockdown_db';

	/**
	 * Option holding unlock-link events.
	 */
	const EVENTS = 'admin_ip_lockdown_events';

	/**
	 * Days blocked attempts are kept.
	 */
	const KEEP_DAYS = 30;

	/**
	 * Most rows kept, whatever their age (a large botnet makes a row per address).
	 */
	const MAX_ROWS = 100000;

	/**
	 * Most unlock events kept.
	 */
	const MAX_EVENTS = 50;

	/**
	 * What was blocked: wp-login.php, wp-admin, xmlrpc.php, a staff sign-in
	 * elsewhere (shop login form, XML-RPC), or a staff session.
	 */
	const KINDS = array( 'login', 'admin', 'xmlrpc', 'signin', 'session' );

	/**
	 * Attempts already recorded during this request.
	 *
	 * @var array<string,bool>
	 */
	private static $recorded = array();

	/**
	 * Table name.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;

		return $wpdb->prefix . 'ailock_log';
	}

	/**
	 * Create or update the table.
	 *
	 * @return void
	 */
	public static function install() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table   = self::table();
		$charset = $wpdb->get_charset_collate();

		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				ip varchar(45) NOT NULL DEFAULT '',
				day date NOT NULL,
				kinds varchar(64) NOT NULL DEFAULT '',
				hits int(10) unsigned NOT NULL DEFAULT 0,
				first_seen datetime NOT NULL,
				last_seen datetime NOT NULL,
				path varchar(191) NOT NULL DEFAULT '',
				PRIMARY KEY  (id),
				UNIQUE KEY ip_day (ip,day),
				KEY last_seen (last_seen)
			) {$charset};"
		);

		update_option( self::DB_OPTION, self::DB_VERSION, true );
	}

	/**
	 * Install the table if this version hasn't yet.
	 *
	 * @return void
	 */
	public static function maybe_install() {
		if ( self::DB_VERSION !== get_option( self::DB_OPTION ) ) {
			self::install();
		}
	}

	/**
	 * The path of this request, without the query string, safe to store.
	 *
	 * @return string
	 */
	public static function current_path() {
		$uri  = Admin_IP_Lockdown_Request::server( 'REQUEST_URI' );
		$path = (string) strtok( $uri, '?#' );
		$path = preg_replace( '/[^\x21-\x7e]/', '', $path );

		return substr( $path, 0, 190 );
	}

	/**
	 * Count a blocked attempt.
	 *
	 * @param string $ip   Address (already validated).
	 * @param string $kind One of {@see KINDS}.
	 * @return void
	 */
	public static function record( $ip, $kind ) {
		global $wpdb;

		if ( ! Admin_IP_Lockdown_Plugin::settings()['log'] || ! in_array( $kind, self::KINDS, true ) ) {
			return;
		}

		$ip = Admin_IP_Lockdown_IP::normalize( $ip );

		if ( '' === $ip || isset( self::$recorded[ $ip . $kind ] ) || self::DB_VERSION !== get_option( self::DB_OPTION ) ) {
			return;
		}

		self::$recorded[ $ip . $kind ] = true;

		$table = self::table();
		$now   = gmdate( 'Y-m-d H:i:s' );
		$path  = self::current_path();

		$suppress = $wpdb->suppress_errors( true );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table; a write.
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$table} (ip, day, kinds, hits, first_seen, last_seen, path) VALUES (%s, %s, %s, 1, %s, %s, %s)
				ON DUPLICATE KEY UPDATE hits = hits + 1, last_seen = %s, path = %s,
				kinds = IF(FIND_IN_SET(%s, kinds), kinds, LEFT(CONCAT(kinds, ',', %s), 64))",
				$ip,
				gmdate( 'Y-m-d' ),
				$kind,
				$now,
				$now,
				$path,
				$now,
				$path,
				$kind,
				$kind
			)
		);
		// phpcs:enable

		$wpdb->suppress_errors( $suppress );
	}

	/**
	 * Delete old rows (daily).
	 *
	 * @return void
	 */
	public static function prune() {
		global $wpdb;

		if ( self::DB_VERSION !== get_option( self::DB_OPTION ) ) {
			return;
		}

		$table = self::table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE day < %s", gmdate( 'Y-m-d', time() - self::KEEP_DAYS * DAY_IN_SECONDS ) ) );

		$rows = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

		if ( $rows > self::MAX_ROWS ) {
			$cutoff = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} ORDER BY id DESC LIMIT 1 OFFSET %d", self::MAX_ROWS ) );

			if ( $cutoff ) {
				$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id <= %d", (int) $cutoff ) );
			}
		}
		// phpcs:enable
	}

	/**
	 * Headline numbers for the Activity tab.
	 *
	 * @return array{today:int,week:int,ips:int,unlocks:int}
	 */
	public static function stats() {
		global $wpdb;

		$stats = array(
			'today'   => 0,
			'week'    => 0,
			'ips'     => 0,
			'unlocks' => 0,
		);

		$since = time() - 30 * DAY_IN_SECONDS;

		foreach ( self::events() as $event ) {
			if ( 'used' === $event['type'] && $event['time'] >= $since ) {
				++$stats['unlocks'];
			}
		}

		if ( self::DB_VERSION !== get_option( self::DB_OPTION ) ) {
			return $stats;
		}

		$table = self::table();
		$week  = gmdate( 'Y-m-d', time() - 6 * DAY_IN_SECONDS );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table, admin page only.
		$stats['today'] = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COALESCE(SUM(hits), 0) FROM {$table} WHERE day = %s", gmdate( 'Y-m-d' ) ) );
		$stats['week']  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COALESCE(SUM(hits), 0) FROM {$table} WHERE day >= %s", $week ) );
		$stats['ips']   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT ip) FROM {$table} WHERE day >= %s", $week ) );
		// phpcs:enable

		return $stats;
	}

	/**
	 * The most recently blocked addresses over the last 7 days, one row each.
	 *
	 * @param int $limit Rows.
	 * @return array<int,array{ip:string,hits:int,last_seen:string,kinds:string[],path:string}>
	 */
	public static function recent( $limit = 25 ) {
		global $wpdb;

		if ( self::DB_VERSION !== get_option( self::DB_OPTION ) ) {
			return array();
		}

		$table = self::table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table, admin page only.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip, SUM(hits) AS hits, MAX(last_seen) AS last_seen, GROUP_CONCAT(kinds SEPARATOR ',') AS kinds,
				SUBSTRING_INDEX(GROUP_CONCAT(path ORDER BY last_seen DESC SEPARATOR '\n'), '\n', 1) AS path
				FROM {$table} WHERE day >= %s GROUP BY ip ORDER BY last_seen DESC LIMIT %d",
				gmdate( 'Y-m-d', time() - 6 * DAY_IN_SECONDS ),
				max( 1, (int) $limit )
			),
			ARRAY_A
		);
		// phpcs:enable

		$out = array();

		foreach ( (array) $rows as $row ) {
			$out[] = array(
				'ip'        => (string) $row['ip'],
				'hits'      => (int) $row['hits'],
				'last_seen' => (string) $row['last_seen'],
				'kinds'     => array_values( array_intersect( self::KINDS, explode( ',', (string) $row['kinds'] ) ) ),
				'path'      => (string) $row['path'],
			);
		}

		return $out;
	}

	/**
	 * Empty the log of blocked attempts and unlock events.
	 *
	 * @return void
	 */
	public static function clear() {
		global $wpdb;

		if ( self::DB_VERSION === get_option( self::DB_OPTION ) ) {
			$table = self::table();
			$wpdb->query( "DELETE FROM {$table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Own table.
		}

		delete_option( self::EVENTS );
	}

	/**
	 * Note an unlock-link event.
	 *
	 * @param string $type    requested, used, removed, kept or test.
	 * @param int    $user_id Account involved.
	 * @param string $ip      Address involved.
	 * @return void
	 */
	public static function event( $type, $user_id, $ip ) {
		$events   = self::events();
		$events[] = array(
			'type' => (string) $type,
			'time' => time(),
			'user' => (int) $user_id,
			'ip'   => (string) $ip,
		);

		update_option( self::EVENTS, array_slice( $events, -self::MAX_EVENTS ), false );
	}

	/**
	 * Unlock-link events, oldest first.
	 *
	 * @return array<int,array{type:string,time:int,user:int,ip:string}>
	 */
	public static function events() {
		$events = get_option( self::EVENTS, array() );
		$out    = array();

		foreach ( is_array( $events ) ? $events : array() as $event ) {
			if ( is_array( $event ) && isset( $event['type'], $event['time'] ) ) {
				$out[] = array(
					'type' => (string) $event['type'],
					'time' => (int) $event['time'],
					'user' => isset( $event['user'] ) ? (int) $event['user'] : 0,
					'ip'   => isset( $event['ip'] ) ? (string) $event['ip'] : '',
				);
			}
		}

		return $out;
	}
}
