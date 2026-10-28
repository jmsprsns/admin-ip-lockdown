<?php
/**
 * Admin side: the Content Powered > Admin IP Lockdown page and the Plugins-screen link.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Settings page controller.
 */
final class Admin_IP_Lockdown_Admin {

	/**
	 * Settings page slug, also used as the settings group.
	 */
	const PAGE = 'admin-ip-lockdown';

	/**
	 * Lucide icon shown beside the menu item and page title.
	 */
	const ICON = 'lock-keyhole';

	/**
	 * Settings tabs: id => Lucide icon.
	 */
	const TABS = array(
		'access'     => 'list-checks',
		'protection' => 'shield-half',
		'recovery'   => 'life-buoy',
		'detection'  => 'radar',
		'activity'   => 'activity',
	);

	/**
	 * The admin-post.php action (and nonce prefix) for the page's buttons.
	 */
	const ACTION = 'admin_ip_lockdown';

	/**
	 * Lucide icon per entry type.
	 */
	const TYPE_ICONS = array(
		'ip'    => 'map-pin',
		'range' => 'network',
		'host'  => 'house-wifi',
	);

	/**
	 * Plugin instance.
	 *
	 * @var Admin_IP_Lockdown_Plugin
	 */
	private $plugin;

	/**
	 * Hook suffix of the settings page.
	 *
	 * @var string
	 */
	private $hook_suffix = '';

	/**
	 * Constructor.
	 *
	 * @param Admin_IP_Lockdown_Plugin $plugin Plugin instance.
	 */
	public function __construct( Admin_IP_Lockdown_Plugin $plugin ) {
		$this->plugin = $plugin;

		Admin_IP_Lockdown_Menu::init();
		Admin_IP_Lockdown_Feedback::init();

		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_init', array( $this, 'privacy_policy_text' ) );
		add_action( 'admin_head', array( $this, 'print_menu_icon_style' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle_action' ) );
		add_action( 'admin_notices', array( $this, 'plugins_screen_notice' ) );

		add_filter(
			'plugin_action_links_' . plugin_basename( ADMIN_IP_LOCKDOWN_FILE ),
			array( $this, 'add_settings_link' )
		);
	}

	/**
	 * Add a "Settings" link to the plugin's row on the Plugins screen.
	 *
	 * @param array $links Existing action links (Deactivate, etc.).
	 * @return array
	 */
	public function add_settings_link( $links ) {
		if ( ! is_array( $links ) ) {
			return $links;
		}

		$settings_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'admin.php?page=' . self::PAGE ) ),
			esc_html__( 'Settings', 'admin-ip-lockdown' )
		);

		array_unshift( $links, $settings_link );

		return $links;
	}

	/**
	 * Add the page under the shared Content Powered menu.
	 *
	 * @return void
	 */
	public function register_menu() {
		$icon       = Admin_IP_Lockdown_Icons::get( self::ICON, 17, 'admin-ip-lockdown-menu-icon' );
		$menu_title = $icon . '<span class="admin-ip-lockdown-menu-label">' . esc_html__( 'Admin IP Lockdown', 'admin-ip-lockdown' ) . '</span>';

		$this->hook_suffix = add_submenu_page(
			Admin_IP_Lockdown_Menu::SLUG,
			__( 'Admin IP Lockdown', 'admin-ip-lockdown' ),
			$menu_title,
			'manage_options',
			self::PAGE,
			array( $this, 'render_page' )
		);

		if ( $this->hook_suffix ) {
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
			add_filter( 'admin_body_class', array( $this, 'body_class' ) );
		}
	}

	/**
	 * Mark the settings page's <body>, so its header can run edge to edge.
	 *
	 * @param string $classes Space-separated body classes.
	 * @return string
	 */
	public function body_class( $classes ) {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;

		return $screen && $screen->id === $this->hook_suffix ? $classes . ' ailock-settings-page' : $classes;
	}

	/**
	 * Register the setting. The tabs are switched in the browser, so one
	 * form saves every tab at once.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			self::PAGE,
			Admin_IP_Lockdown_Plugin::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize' ),
				'default'           => Admin_IP_Lockdown_Plugin::defaults(),
			)
		);
	}

	/**
	 * Suggested wording for the site's privacy policy (Settings > Privacy).
	 *
	 * @return void
	 */
	public function privacy_policy_text() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}

		wp_add_privacy_policy_content(
			__( 'Admin IP Lockdown', 'admin-ip-lockdown' ),
			'<p>' . esc_html__( 'When someone tries to reach this site\'s admin area or login page from a network that isn\'t approved, their IP address, the page they asked for and the time are logged for up to 30 days to protect the site from unauthorised access. When an administrator uses an emailed unlock link, the IP address it was opened from is kept while that access lasts.', 'admin-ip-lockdown' ) . '</p>'
		);
	}

	/**
	 * Cut text to a length, multibyte-safe.
	 *
	 * @param string $text   Text.
	 * @param int    $length Most characters.
	 * @return string
	 */
	private static function cut( $text, $length ) {
		return function_exists( 'mb_substr' ) ? mb_substr( (string) $text, 0, $length, 'UTF-8' ) : substr( (string) $text, 0, $length );
	}

	/**
	 * Clean the submitted settings before they are saved, and refuse any
	 * change that would lock out the person saving it.
	 *
	 * @param mixed $input Raw form values.
	 * @return array<string,mixed>
	 */
	public function sanitize( $input ) {
		$stored = get_option( Admin_IP_Lockdown_Plugin::OPTION, array() );
		$old    = Admin_IP_Lockdown_Plugin::normalize( is_array( $stored ) ? $stored : array() );

		if ( ! is_array( $input ) ) {
			return $old;
		}

		$problems = array();
		$entries  = array();
		$seen     = array();
		$hosts    = 0;
		$added    = array();

		foreach ( $old['entries'] as $entry ) {
			$added[ $entry['value'] ] = $entry['added'];
		}

		$rows = isset( $input['entries'] ) && is_array( $input['entries'] ) ? $input['entries'] : array();

		foreach ( $rows as $row ) {
			$raw = is_array( $row ) && isset( $row['value'] ) && is_string( $row['value'] ) ? $row['value'] : '';

			if ( '' === trim( $raw ) ) {
				continue;
			}

			$parsed = Admin_IP_Lockdown_IP::parse_entry( $raw );

			if ( is_wp_error( $parsed ) ) {
				$problems[] = '<code>' . esc_html( self::cut( wp_strip_all_tags( $raw ), 80 ) ) . '</code>: ' . esc_html( $parsed->get_error_message() );
				continue;
			}

			if ( isset( $seen[ $parsed['value'] ] ) ) {
				continue;
			}

			if ( 'host' === $parsed['type'] && ++$hosts > Admin_IP_Lockdown_Plugin::MAX_HOSTS ) {
				/* translators: 1: hostname, 2: most hostnames allowed. */
				$problems[] = sprintf( esc_html__( '%1$s wasn\'t added: at most %2$d hostnames can be on the list.', 'admin-ip-lockdown' ), '<code>' . esc_html( $parsed['value'] ) . '</code>', Admin_IP_Lockdown_Plugin::MAX_HOSTS );
				continue;
			}

			if ( count( $entries ) >= Admin_IP_Lockdown_Plugin::MAX_ENTRIES ) {
				/* translators: %d: most entries allowed. */
				$problems[] = sprintf( esc_html__( 'The list holds at most %d entries; the rest weren\'t added.', 'admin-ip-lockdown' ), Admin_IP_Lockdown_Plugin::MAX_ENTRIES );
				break;
			}

			$seen[ $parsed['value'] ] = true;

			$when = isset( $added[ $parsed['value'] ] ) ? $added[ $parsed['value'] ] : ( isset( $row['added'] ) ? absint( $row['added'] ) : 0 );

			$entries[] = array(
				'type'  => $parsed['type'],
				'value' => $parsed['value'],
				'label' => isset( $row['label'] ) && is_string( $row['label'] ) ? self::cut( sanitize_text_field( $row['label'] ), 60 ) : '',
				'added' => $when && $when <= time() ? $when : time(),
			);
		}

		// Trusted proxies: addresses and ranges only.
		$proxy_text = '';

		if ( isset( $input['proxies'] ) ) {
			$proxy_text = is_array( $input['proxies'] ) ? implode( "\n", array_filter( $input['proxies'], 'is_string' ) ) : (string) $input['proxies'];
		}

		$proxies = array();

		foreach ( preg_split( '/[\s,;]+/', $proxy_text, -1, PREG_SPLIT_NO_EMPTY ) as $item ) {
			$parsed = Admin_IP_Lockdown_IP::parse_entry( $item );

			if ( is_wp_error( $parsed ) || 'host' === $parsed['type'] ) {
				/* translators: %s: what was entered. */
				$problems[] = sprintf( esc_html__( 'Trusted proxies: %s isn\'t an IP address or range.', 'admin-ip-lockdown' ), '<code>' . esc_html( self::cut( $item, 80 ) ) . '</code>' );
				continue;
			}

			$proxies[] = $parsed['value'];
		}

		$proxies = array_slice( array_values( array_unique( $proxies ) ), 0, Admin_IP_Lockdown_Plugin::MAX_PROXIES );

		$flag = function ( $key ) use ( $input ) {
			return empty( $input[ $key ] ) ? 0 : 1;
		};

		$out = Admin_IP_Lockdown_Plugin::normalize(
			array(
				'enabled'        => $flag( 'enabled' ),
				'entries'        => $entries,
				'protect_admin'  => $flag( 'protect_admin' ),
				'protect_login'  => $flag( 'protect_login' ),
				'protect_xmlrpc' => $flag( 'protect_xmlrpc' ),
				'staff'          => isset( $input['staff'] ) ? $input['staff'] : '',
				'login_guard'    => $flag( 'login_guard' ),
				'session_guard'  => $flag( 'session_guard' ),
				'app_passwords'  => $flag( 'app_passwords' ),
				'unlock_email'   => $flag( 'unlock_email' ),
				'unlock_hours'   => isset( $input['unlock_hours'] ) ? (int) $input['unlock_hours'] : 24,
				'notify_unlock'  => $flag( 'notify_unlock' ),
				'message'        => isset( $input['message'] ) && is_string( $input['message'] ) ? self::cut( sanitize_textarea_field( $input['message'] ), 500 ) : '',
				'cloudflare'     => $flag( 'cloudflare' ),
				'proxies'        => $proxies,
				'proxy_header'   => isset( $input['proxy_header'] ) ? $input['proxy_header'] : '',
				'log'            => $flag( 'log' ),
			)
		);

		// Look new hostnames up now, so the check below and the list can use them.
		$all_hosts = Admin_IP_Lockdown_Access::hosts( $out );
		$new_hosts = array_diff( $all_hosts, array_keys( Admin_IP_Lockdown_DNS::cache() ) );

		if ( $new_hosts ) {
			Admin_IP_Lockdown_DNS::refresh( $new_hosts, true );
		}

		Admin_IP_Lockdown_DNS::prune( $all_hosts );

		foreach ( $new_hosts as $host ) {
			if ( ! Admin_IP_Lockdown_DNS::ips( $host ) ) {
				/* translators: %s: hostname. */
				$problems[] = sprintf( esc_html__( '%s doesn\'t resolve to any address right now, so it won\'t let anyone in until it does.', 'admin-ip-lockdown' ), '<code>' . esc_html( $host ) . '</code>' );
			}
		}

		if ( $out['enabled'] && ! Admin_IP_Lockdown_Plugin::disabled_by_constant() ) {
			// Under the new settings, including how the visitor IP is read.
			$me = Admin_IP_Lockdown_Request::resolve( $out )['ip'];

			if ( ! Admin_IP_Lockdown_IP::supported() ) {
				$out['enabled'] = 0;
				add_settings_error( self::PAGE, 'ailock-unsupported', esc_html__( 'Lockdown can\'t switch on: this server\'s PHP was built without IPv6 support (inet_pton), which the plugin needs to compare addresses.', 'admin-ip-lockdown' ), 'error' );
			} elseif ( null === Admin_IP_Lockdown_Access::match( $me, $out ) ) {
				$me_html = '<code>' . esc_html( '' !== $me ? $me : __( 'unknown', 'admin-ip-lockdown' ) ) . '</code>';

				if ( $old['enabled'] ) {
					add_settings_error(
						self::PAGE,
						'ailock-lockout',
						/* translators: %s: the visitor's IP address. */
						sprintf( esc_html__( 'Nothing was saved. With these changes your own IP address (%s) wouldn\'t be allowed, and you\'d be locked out as soon as the page reloads. Add it to the list, then save again.', 'admin-ip-lockdown' ), $me_html ),
						'error'
					);

					return is_array( $stored ) ? $stored : $old;
				}

				$out['enabled'] = 0;
				add_settings_error(
					self::PAGE,
					'ailock-lockout',
					/* translators: %s: the visitor's IP address. */
					sprintf( esc_html__( 'Lockdown is still off: your IP address (%s) isn\'t on the allowed list, so switching it on would lock you out. Add it, then switch the lockdown on again. Your other changes were saved.', 'admin-ip-lockdown' ), $me_html ),
					'error'
				);
			} elseif ( ! $old['enabled'] ) {
				add_settings_error( self::PAGE, 'ailock-on', esc_html__( 'Lockdown is on. Only the addresses on your list can reach wp-admin and the login page.', 'admin-ip-lockdown' ), 'success' );
			}
		}

		if ( $problems ) {
			add_settings_error( self::PAGE, 'ailock-problems', esc_html__( 'Some entries weren\'t saved:', 'admin-ip-lockdown' ) . '<br>' . implode( '<br>', $problems ), 'warning' );
		}

		// Core only says "Settings saved." when nothing else was reported.
		if ( get_settings_errors( self::PAGE ) ) {
			add_settings_error( self::PAGE, 'ailock-saved', esc_html__( 'Settings saved.', 'admin-ip-lockdown' ), 'success' );
		}

		return $out;
	}

	/**
	 * Tiny inline style so the menu icon sits neatly beside its label, even
	 * when a long plugin name wraps onto a second line.
	 *
	 * @return void
	 */
	public function print_menu_icon_style() {
		echo '<style id="admin-ip-lockdown-menu-icon-style">'
			. '#adminmenu a:has(>.admin-ip-lockdown-menu-icon){display:flex;align-items:flex-start;gap:7px}'
			. '#adminmenu .admin-ip-lockdown-menu-icon{flex:none;margin-top:1px;opacity:.7}'
			. '#adminmenu li.current .admin-ip-lockdown-menu-icon,#adminmenu a:hover .admin-ip-lockdown-menu-icon,#adminmenu a:focus .admin-ip-lockdown-menu-icon{opacity:1}'
			. '</style>';
	}

	/**
	 * Load the settings-page styles and scripts.
	 *
	 * @param string $hook Current admin page hook suffix.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( $hook !== $this->hook_suffix ) {
			return;
		}

		wp_enqueue_style( 'admin-ip-lockdown-admin', ADMIN_IP_LOCKDOWN_URL . 'assets/admin.css', array(), ADMIN_IP_LOCKDOWN_VERSION );
		wp_enqueue_script( 'admin-ip-lockdown-admin', ADMIN_IP_LOCKDOWN_URL . 'assets/admin.js', array(), ADMIN_IP_LOCKDOWN_VERSION, true );

		$me = Admin_IP_Lockdown_Request::client_ip();

		wp_localize_script(
			'admin-ip-lockdown-admin',
			'admin_ip_lockdown_admin',
			array(
				'myIp'      => $me,
				'myEntry'   => Admin_IP_Lockdown_IP::is_v6( $me ) ? Admin_IP_Lockdown_IP::network64( $me ) : $me,
				'myAllowed' => null !== Admin_IP_Lockdown_Access::match( $me, Admin_IP_Lockdown_Plugin::settings() ),
				'i18n'      => array(
					'myLabel'       => __( 'My IP', 'admin-ip-lockdown' ),
					'removeConfirm' => __( 'End this network\'s temporary access now?', 'admin-ip-lockdown' ),
					'clearConfirm'  => __( 'Clear the log of blocked attempts and unlock links?', 'admin-ip-lockdown' ),
					'notListed'     => __( 'Your IP address isn\'t on the list yet. Add it before switching the lockdown on, or the save will keep it off.', 'admin-ip-lockdown' ),
					'unsaved'       => __( 'You have unsaved changes.', 'admin-ip-lockdown' ),
				),
			)
		);
	}

	/**
	 * Inline icon.
	 *
	 * @param string $name Lucide icon.
	 * @param int    $size Size in px.
	 * @return string
	 */
	private static function icon( $name, $size = 18 ) {
		return Admin_IP_Lockdown_Icons::get( $name, $size );
	}

	/**
	 * Echo an inline icon.
	 *
	 * @param string $name Lucide icon.
	 * @param int    $size Size in px.
	 * @return void
	 */
	private static function the_icon( $name, $size = 18 ) {
		echo self::icon( $name, $size ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Bundled SVG.
	}

	/**
	 * Link that runs one of the page's actions through admin-post.php.
	 *
	 * @param string $op   Action.
	 * @param array  $args Extra query arguments.
	 * @return string
	 */
	private static function action_url( $op, array $args = array() ) {
		return wp_nonce_url(
			add_query_arg(
				array_merge(
					array(
						'action' => self::ACTION,
						'op'     => $op,
					),
					$args
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION . '_' . $op
		);
	}

	/**
	 * Back to the page, on a tab, with a notice.
	 *
	 * @param string $notice Notice code.
	 * @param string $tab    Tab id.
	 * @return void
	 */
	private static function back( $notice, $tab ) {
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE . '&ailock-notice=' . rawurlencode( $notice ) . '#' . $tab ) );
		exit;
	}

	/**
	 * Handle the page's buttons (admin-post.php).
	 *
	 * @return void
	 */
	public function handle_action() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Verified per action just below.
		$op = isset( $_GET['op'] ) && is_string( $_GET['op'] ) ? sanitize_key( $_GET['op'] ) : '';

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'admin-ip-lockdown' ), 403 );
		}

		check_admin_referer( self::ACTION . '_' . $op );

		$value = isset( $_GET['value'] ) && is_string( $_GET['value'] ) ? sanitize_text_field( wp_unslash( $_GET['value'] ) ) : '';
		// phpcs:enable

		switch ( $op ) {
			case 'temp-remove':
				$this->remove_temporary( $value );
				break;

			case 'temp-keep':
				$item = null;

				foreach ( Admin_IP_Lockdown_Access::temporary() as $candidate ) {
					if ( $candidate['value'] === $value ) {
						$item = $candidate;
					}
				}

				if ( ! $item ) {
					self::back( 'gone', 'access' );
				}

				$user = get_userdata( $item['user'] );
				/* translators: %s: username. */
				$label = $user ? sprintf( __( 'Unlocked by %s', 'admin-ip-lockdown' ), $user->user_login ) : __( 'Unlocked by email link', 'admin-ip-lockdown' );
				$code  = $this->add_entry( $value, $label );

				if ( 'allowed' === $code ) {
					Admin_IP_Lockdown_Access::remove_temporary( $value );
					Admin_IP_Lockdown_Log::event( 'kept', get_current_user_id(), $value );
				}

				self::back( 'allowed' === $code ? 'kept' : $code, 'access' );
				break;

			case 'allow':
				self::back( $this->add_entry( $value, __( 'Allowed from the activity log', 'admin-ip-lockdown' ) ), 'access' );
				break;

			case 'clear':
				Admin_IP_Lockdown_Log::clear();
				self::back( 'cleared', 'activity' );
				break;

			case 'test-email':
				self::back( Admin_IP_Lockdown_Unlock::send_test( wp_get_current_user() ) ? 'test-sent' : 'test-failed', 'recovery' );
				break;

			case 'dns':
				Admin_IP_Lockdown_DNS::refresh( Admin_IP_Lockdown_Access::hosts( Admin_IP_Lockdown_Plugin::settings() ), true );
				self::back( 'dns', 'access' );
				break;

			case 'cloudflare':
				self::back( Admin_IP_Lockdown_Cloudflare::refresh() ? 'cloudflare' : 'cloudflare-failed', 'detection' );
				break;

			case 'preview':
				Admin_IP_Lockdown_Blocked::render( Admin_IP_Lockdown_Request::client_ip(), true );
				break;
		}

		self::back( '', 'access' );
	}

	/**
	 * End a network's temporary access, unless that's how the person doing
	 * it is getting in right now.
	 *
	 * @param string $value Network.
	 * @return void
	 */
	private function remove_temporary( $value ) {
		$before = get_option( Admin_IP_Lockdown_Access::TEMPORARY, array() );

		if ( ! Admin_IP_Lockdown_Access::remove_temporary( $value ) ) {
			self::back( 'gone', 'access' );
		}

		if ( Admin_IP_Lockdown_Plugin::enforcing() && null === Admin_IP_Lockdown_Access::match( Admin_IP_Lockdown_Request::client_ip(), Admin_IP_Lockdown_Plugin::settings() ) ) {
			update_option( Admin_IP_Lockdown_Access::TEMPORARY, $before, true );
			self::back( 'self', 'access' );
		}

		Admin_IP_Lockdown_Log::event( 'removed', get_current_user_id(), $value );
		self::back( 'removed', 'access' );
	}

	/**
	 * Put an address on the allowed list.
	 *
	 * @param string $value Address or range.
	 * @param string $label Label.
	 * @return string Notice code.
	 */
	private function add_entry( $value, $label ) {
		$parsed = Admin_IP_Lockdown_IP::parse_entry( $value );

		if ( is_wp_error( $parsed ) || 'host' === $parsed['type'] ) {
			return 'invalid';
		}

		$settings = Admin_IP_Lockdown_Plugin::settings();

		foreach ( $settings['entries'] as $entry ) {
			if ( $entry['value'] === $parsed['value'] ) {
				return 'exists';
			}
		}

		if ( count( $settings['entries'] ) >= Admin_IP_Lockdown_Plugin::MAX_ENTRIES ) {
			return 'full';
		}

		$settings['entries'][] = array(
			'type'  => $parsed['type'],
			'value' => $parsed['value'],
			'label' => self::cut( $label, 60 ),
			'added' => time(),
		);

		update_option( Admin_IP_Lockdown_Plugin::OPTION, $settings );

		return 'allowed';
	}

	/**
	 * Message for a notice code from {@see back()}.
	 *
	 * @param string $code Code.
	 * @return array{0:string,1:string}|null Type and text.
	 */
	private static function notice( $code ) {
		switch ( $code ) {
			case 'removed':
				return array( 'success', __( 'Temporary access ended.', 'admin-ip-lockdown' ) );
			case 'kept':
				return array( 'success', __( 'Moved to the allowed list for good.', 'admin-ip-lockdown' ) );
			case 'allowed':
				return array( 'success', __( 'Added to the allowed list.', 'admin-ip-lockdown' ) );
			case 'exists':
				return array( 'info', __( 'That address is already on the allowed list.', 'admin-ip-lockdown' ) );
			case 'full':
				return array( 'error', __( 'The allowed list is full.', 'admin-ip-lockdown' ) );
			case 'invalid':
				return array( 'error', __( 'That isn\'t a valid IP address or range.', 'admin-ip-lockdown' ) );
			case 'gone':
				return array( 'info', __( 'That temporary access had already ended.', 'admin-ip-lockdown' ) );
			case 'self':
				return array( 'error', __( 'Not removed: that\'s how you\'re getting in right now, so removing it would lock you out. Add your IP address to the allowed list first.', 'admin-ip-lockdown' ) );
			case 'cleared':
				return array( 'success', __( 'Activity cleared.', 'admin-ip-lockdown' ) );
			case 'test-sent':
				/* translators: %s: email address. */
				return array( 'success', sprintf( __( 'Test email sent to %s. If it doesn\'t arrive, unlock links won\'t either: check this site\'s email setup.', 'admin-ip-lockdown' ), wp_get_current_user()->user_email ) );
			case 'test-failed':
				return array( 'error', __( 'WordPress couldn\'t send the test email, so unlock links wouldn\'t arrive either. Check this site\'s email setup (an SMTP plugin usually fixes it).', 'admin-ip-lockdown' ) );
			case 'dns':
				return array( 'success', __( 'Hostnames looked up again.', 'admin-ip-lockdown' ) );
			case 'cloudflare':
				return array( 'success', __( 'Cloudflare\'s address list was refreshed.', 'admin-ip-lockdown' ) );
			case 'cloudflare-failed':
				return array( 'error', __( 'Couldn\'t fetch Cloudflare\'s address list right now. The built-in list is still used.', 'admin-ip-lockdown' ) );
		}

		return null;
	}

	/**
	 * Remind admins on the Plugins screen that the lockdown isn't on yet.
	 *
	 * @return void
	 */
	public function plugins_screen_notice() {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;

		if ( ! $screen || 'plugins' !== $screen->id || ! current_user_can( 'manage_options' ) || Admin_IP_Lockdown_Plugin::settings()['enabled'] ) {
			return;
		}

		printf(
			'<div class="notice notice-info"><p>%1$s <a href="%2$s">%3$s</a></p></div>',
			esc_html__( 'Admin IP Lockdown is installed, but the lockdown is off. Your IP address is already on its list.', 'admin-ip-lockdown' ),
			esc_url( admin_url( 'admin.php?page=' . self::PAGE ) ),
			esc_html__( 'Review the list and switch it on', 'admin-ip-lockdown' )
		);
	}

	/**
	 * Tab name.
	 *
	 * @param string $id Tab id.
	 * @return string
	 */
	private static function tab_label( $id ) {
		switch ( $id ) {
			case 'access':
				return __( 'Allowed IPs', 'admin-ip-lockdown' );
			case 'protection':
				return __( 'Protection', 'admin-ip-lockdown' );
			case 'recovery':
				return __( 'Recovery', 'admin-ip-lockdown' );
			case 'detection':
				return __( 'IP detection', 'admin-ip-lockdown' );
		}

		return __( 'Activity', 'admin-ip-lockdown' );
	}

	/**
	 * The page's boxes, in order: the tab each one is on, its icon, title,
	 * intro and what draws it.
	 *
	 * @return array<string,array>
	 */
	private function sections() {
		$sections = array(
			'lockdown'  => array( 'access', 'power', __( 'Lockdown', 'admin-ip-lockdown' ), '', 'render_lockdown' ),
			'list'      => array( 'access', 'list-checks', __( 'Allowed addresses', 'admin-ip-lockdown' ), __( 'Only these can reach wp-admin and the login page. Add an IPv4 or IPv6 address, a range (203.0.113.0/24 or 203.0.113.*), or a dynamic DNS hostname for a home connection whose IP changes.', 'admin-ip-lockdown' ), 'render_list' ),
			'temporary' => array( 'access', 'timer', __( 'Temporary access', 'admin-ip-lockdown' ), __( 'Networks let in for a while by an emailed unlock link. Keep one to move it to the list for good.', 'admin-ip-lockdown' ), 'render_temporary' ),
			'config'    => array( 'access', 'file-code', __( 'Allowed in wp-config.php', 'admin-ip-lockdown' ), __( 'Set with ADMIN_IP_LOCKDOWN_ALLOW in wp-config.php. Edit them there.', 'admin-ip-lockdown' ), 'render_config' ),
			'locked'    => array( 'protection', 'lock', __( 'What\'s locked', 'admin-ip-lockdown' ), __( 'Addresses that aren\'t allowed get an "Access restricted" page instead of these.', 'admin-ip-lockdown' ), 'render_locked' ),
			'staff'     => array( 'protection', 'users', __( 'Staff accounts', 'admin-ip-lockdown' ), __( 'Closes the other ways in: signing in through a different login form, and using a login cookie from somewhere else.', 'admin-ip-lockdown' ), 'render_staff' ),
			'unlock'    => array( 'recovery', 'mail', __( 'Emergency unlock email', 'admin-ip-lockdown' ), __( 'Locked out on a new network? Administrators can email themselves a one-time link from the "Access restricted" page. It lets in the network it\'s opened from, for a limited time.', 'admin-ip-lockdown' ), 'render_unlock' ),
			'page'      => array( 'recovery', 'shield-ban', __( 'Blocked page', 'admin-ip-lockdown' ), __( 'What blocked visitors see. It shows their IP address, so a colleague can tell you what to add.', 'admin-ip-lockdown' ), 'render_blocked_page' ),
			'ways'      => array( 'recovery', 'key-round', __( 'Other ways back in', 'admin-ip-lockdown' ), __( 'If email isn\'t an option, any of these gets you back in.', 'admin-ip-lockdown' ), 'render_ways' ),
			'you'       => array( 'detection', 'scan-eye', __( 'How this site sees you', 'admin-ip-lockdown' ), '', 'render_you' ),
			'cf'        => array( 'detection', 'cloud', __( 'Cloudflare', 'admin-ip-lockdown' ), __( 'Behind Cloudflare, every request arrives from a Cloudflare server. The visitor\'s real address comes in the CF-Connecting-IP header, which is only believed when the request really comes from Cloudflare\'s network, so it can\'t be faked by sending the header directly.', 'admin-ip-lockdown' ), 'render_cloudflare' ),
			'proxy'     => array( 'detection', 'server', __( 'Other proxy or load balancer', 'admin-ip-lockdown' ), __( 'Only needed if your host puts its own proxy, load balancer or firewall (such as Sucuri) in front of WordPress, so every request seems to come from the same address. Most sites leave this empty.', 'admin-ip-lockdown' ), 'render_proxy' ),
			'overview'  => array( 'activity', 'gauge', __( 'Overview', 'admin-ip-lockdown' ), '', 'render_overview' ),
			'blocked'   => array( 'activity', 'ban', __( 'Recently blocked', 'admin-ip-lockdown' ), __( 'Addresses turned away in the last 7 days, newest first.', 'admin-ip-lockdown' ), 'render_blocked' ),
			'events'    => array( 'activity', 'mail-check', __( 'Unlock links', 'admin-ip-lockdown' ), '', 'render_events' ),
			'logging'   => array( 'activity', 'history', __( 'Logging', 'admin-ip-lockdown' ), '', 'render_logging' ),
		);

		if ( ! Admin_IP_Lockdown_Access::temporary() ) {
			unset( $sections['temporary'] );
		}

		if ( ! defined( 'ADMIN_IP_LOCKDOWN_ALLOW' ) ) {
			unset( $sections['config'] );
		}

		return $sections;
	}

	/**
	 * Render the settings page.
	 *
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$settings = Admin_IP_Lockdown_Plugin::settings();
		?>
		<div class="ailock-header">
			<div class="ailock-header-title">
				<span class="ailock-header-icon"><?php self::the_icon( self::ICON, 20 ); ?></span>
				<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
				<span class="ailock-version"><?php echo esc_html( 'v' . ADMIN_IP_LOCKDOWN_VERSION ); ?></span>
				<?php $this->render_state_pill(); ?>
			</div>
			<nav class="ailock-tabs" role="tablist" aria-label="<?php esc_attr_e( 'Settings sections', 'admin-ip-lockdown' ); ?>">
				<?php foreach ( self::TABS as $id => $icon ) : ?>
					<a href="#<?php echo esc_attr( $id ); ?>" class="ailock-tab" role="tab" data-ailock-tab="<?php echo esc_attr( $id ); ?>">
						<?php self::the_icon( $icon, 16 ); ?>
						<?php echo esc_html( self::tab_label( $id ) ); ?>
					</a>
				<?php endforeach; ?>
			</nav>
		</div>

		<div class="wrap ailock-wrap">
			<hr class="wp-header-end">

			<?php
			// Pages outside the Settings menu have to show "Settings saved." themselves.
			// Without a page slug: core files its own messages under "general".
			settings_errors();

			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
			$notice = isset( $_GET['ailock-notice'] ) && is_string( $_GET['ailock-notice'] ) ? self::notice( sanitize_key( $_GET['ailock-notice'] ) ) : null;

			if ( $notice ) {
				printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $notice[0] ), esc_html( $notice[1] ) );
			}

			if ( Admin_IP_Lockdown_Plugin::disabled_by_constant() ) {
				printf(
					'<div class="notice notice-warning"><p>%s</p></div>',
					sprintf(
						/* translators: %s: constant name. */
						esc_html__( 'The lockdown is switched off by %s in wp-config.php. Remove that line to turn it back on.', 'admin-ip-lockdown' ),
						'<code>ADMIN_IP_LOCKDOWN_DISABLE</code>'
					)
				);
			}
			?>

			<form action="options.php" method="post" class="ailock-form">
				<?php settings_fields( self::PAGE ); ?>

				<div id="poststuff">
					<div id="post-body" class="metabox-holder columns-2">
						<div id="post-body-content">
							<?php
							foreach ( $this->sections() as $id => $section ) {
								$this->render_section( $id, $section, $settings );
							}
							?>
						</div>

						<div id="postbox-container-1" class="postbox-container">
							<div class="ailock-sidebar">
								<?php $this->render_sidebar( $settings ); ?>
							</div>
						</div>
					</div>
					<br class="clear">
				</div>
			</form>
		</div>
		<?php
	}

	/**
	 * The on/off pill in the header.
	 *
	 * @return void
	 */
	private function render_state_pill() {
		if ( Admin_IP_Lockdown_Plugin::disabled_by_constant() ) {
			echo '<span class="ailock-state is-warn">' . self::icon( 'triangle-alert', 14 ) . esc_html__( 'Off in wp-config.php', 'admin-ip-lockdown' ) . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Bundled SVG.
		} elseif ( Admin_IP_Lockdown_Plugin::enforcing() ) {
			echo '<span class="ailock-state is-on">' . self::icon( 'lock', 14 ) . esc_html__( 'Lockdown on', 'admin-ip-lockdown' ) . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Bundled SVG.
		} else {
			echo '<span class="ailock-state">' . self::icon( 'lock-open', 14 ) . esc_html__( 'Lockdown off', 'admin-ip-lockdown' ) . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Bundled SVG.
		}
	}

	/**
	 * One box.
	 *
	 * @param string $id       Section id.
	 * @param array  $section  Section from {@see sections()}: panel, icon, title, intro, method.
	 * @param array  $settings Settings.
	 * @return void
	 */
	private function render_section( $id, array $section, array $settings ) {
		list( $panel, $icon, $title, $intro, $method ) = $section;
		?>
		<div class="postbox ailock-box" id="ailock-<?php echo esc_attr( $id ); ?>" data-ailock-panel="<?php echo esc_attr( $panel ); ?>">
			<div class="postbox-header">
				<h2 class="hndle">
					<?php self::the_icon( $icon ); ?>
					<?php echo esc_html( $title ); ?>
				</h2>
			</div>
			<div class="inside">
				<?php if ( '' !== $intro ) : ?>
					<p class="ailock-intro"><?php echo esc_html( $intro ); ?></p>
				<?php endif; ?>
				<?php $this->$method( $settings ); ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Name attribute for a setting.
	 *
	 * @param string $key Setting key.
	 * @return string
	 */
	private static function name( $key ) {
		return Admin_IP_Lockdown_Plugin::OPTION . '[' . $key . ']';
	}

	/**
	 * Checkbox with a label and an optional description.
	 *
	 * @param array  $settings Settings.
	 * @param string $key      Setting key.
	 * @param string $label    Label.
	 * @param string $desc     Description under it.
	 * @return void
	 */
	private static function checkbox( array $settings, $key, $label, $desc = '' ) {
		echo '<div class="ailock-setting">';
		printf(
			'<label class="ailock-check"><input type="checkbox" name="%1$s" value="1" %2$s> <span>%3$s</span></label>',
			esc_attr( self::name( $key ) ),
			checked( 1, (int) $settings[ $key ], false ),
			esc_html( $label )
		);

		if ( '' !== $desc ) {
			echo '<p class="description">' . esc_html( $desc ) . '</p>';
		}

		echo '</div>';
	}

	/**
	 * A setting shown as a card with an icon (checkbox or radio).
	 *
	 * @param string $type    checkbox or radio.
	 * @param string $name    Field name.
	 * @param string $value   Field value.
	 * @param bool   $checked Whether it's selected.
	 * @param string $icon    Lucide icon.
	 * @param string $title   Title.
	 * @param string $desc    Description.
	 * @return void
	 */
	private static function option_card( $type, $name, $value, $checked, $icon, $title, $desc ) {
		?>
		<label class="ailock-option">
			<input type="<?php echo esc_attr( $type ); ?>" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>" <?php checked( $checked ); ?>>
			<span class="ailock-option-icon"><?php self::the_icon( $icon, 18 ); ?></span>
			<span class="ailock-option-text">
				<strong><?php echo esc_html( $title ); ?></strong>
				<span><?php echo esc_html( $desc ); ?></span>
			</span>
		</label>
		<?php
	}

	/**
	 * What lets the current visitor in, in words.
	 *
	 * @param array|null $found From {@see Admin_IP_Lockdown_Access::match()}.
	 * @return string
	 */
	private static function match_text( $found ) {
		if ( ! $found ) {
			return '';
		}

		if ( 'temporary' === $found['source'] ) {
			/* translators: %s: time left, e.g. "5 hours". */
			return sprintf( __( 'Unlocked by an email link for another %s', 'admin-ip-lockdown' ), human_time_diff( time(), $found['entry']['expires'] ) );
		}

		$what = '' !== $found['entry']['label'] && 'config' !== $found['source'] ? $found['entry']['label'] : $found['entry']['value'];

		if ( 'config' === $found['source'] ) {
			/* translators: %s: entry. */
			return sprintf( __( 'Allowed by %s in wp-config.php', 'admin-ip-lockdown' ), $what );
		}

		/* translators: %s: entry label or value. */
		return sprintf( __( 'Allowed by "%s"', 'admin-ip-lockdown' ), $what );
	}

	/**
	 * Allowed IPs: the switch and the visitor's own address.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_lockdown( array $settings ) {
		$me     = Admin_IP_Lockdown_Request::resolve( $settings );
		$ip     = $me['ip'];
		$match  = Admin_IP_Lockdown_Access::match( $ip, $settings );
		$via    = 'cloudflare' === $me['via'] ? __( 'through Cloudflare', 'admin-ip-lockdown' ) : ( 'proxy' === $me['via'] ? __( 'through your proxy', 'admin-ip-lockdown' ) : '' );
		$is_six = Admin_IP_Lockdown_IP::is_v6( $ip );
		?>
		<label class="ailock-master">
			<input type="checkbox" name="<?php echo esc_attr( self::name( 'enabled' ) ); ?>" value="1" data-ailock-enabled <?php checked( 1, $settings['enabled'] ); ?>>
			<span class="ailock-master-text">
				<strong><?php esc_html_e( 'Lock wp-admin and the login page to the addresses below', 'admin-ip-lockdown' ); ?></strong>
				<span><?php esc_html_e( 'Everyone else gets an "Access restricted" page. Your own address is checked when you save, so you can\'t lock yourself out by accident.', 'admin-ip-lockdown' ); ?></span>
			</span>
		</label>
		<p class="ailock-inline-warning" data-ailock-not-listed hidden><?php self::the_icon( 'triangle-alert', 16 ); ?><span></span></p>

		<div class="ailock-you<?php echo $match ? ' is-allowed' : ''; ?>">
			<span class="ailock-you-icon"><?php self::the_icon( $match ? 'user-round-check' : 'user-round-x', 20 ); ?></span>
			<div class="ailock-you-text">
				<span class="ailock-you-label">
					<?php esc_html_e( 'You\'re connecting from', 'admin-ip-lockdown' ); ?>
					<?php if ( '' !== $via ) : ?>
						<span class="ailock-via"><?php echo esc_html( $via ); ?></span>
					<?php endif; ?>
				</span>
				<code class="ailock-you-ip"><?php echo esc_html( '' !== $ip ? $ip : __( 'unknown', 'admin-ip-lockdown' ) ); ?></code>
				<span class="ailock-you-status">
					<?php
					if ( $match ) {
						self::the_icon( 'circle-check', 15 );
						echo esc_html( self::match_text( $match ) );
					} else {
						self::the_icon( 'circle-alert', 15 );
						esc_html_e( 'Not on the list yet', 'admin-ip-lockdown' );
					}
					?>
				</span>
			</div>
			<?php if ( ! $match && '' !== $ip ) : ?>
				<button type="button" class="button button-primary" data-ailock-add-mine><?php self::the_icon( 'plus', 16 ); ?><?php echo $is_six ? esc_html__( 'Add my network (/64)', 'admin-ip-lockdown' ) : esc_html__( 'Add my IP', 'admin-ip-lockdown' ); ?></button>
			<?php endif; ?>
		</div>

		<?php if ( $is_six ) : ?>
			<p class="ailock-hint"><?php self::the_icon( 'info', 15 ); ?><span><?php esc_html_e( 'Your connection uses IPv6. Devices get a new IPv6 address often, so allow your network (/64) rather than this one address. Browsers can also switch between IPv4 and IPv6: if you get blocked, add the address the blocked page shows too.', 'admin-ip-lockdown' ); ?></span></p>
		<?php endif; ?>
		<?php
	}

	/**
	 * Allowed IPs: the editable list.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_list( array $settings ) {
		$me    = Admin_IP_Lockdown_Request::client_ip();
		$cache = Admin_IP_Lockdown_DNS::cache();
		?>
		<div class="ailock-entries" data-ailock-entries>
			<div class="ailock-entries-head" aria-hidden="true">
				<span></span>
				<span><?php esc_html_e( 'Address, range or hostname', 'admin-ip-lockdown' ); ?></span>
				<span><?php esc_html_e( 'Label', 'admin-ip-lockdown' ); ?></span>
				<span><?php esc_html_e( 'Status', 'admin-ip-lockdown' ); ?></span>
				<span></span>
			</div>
			<?php
			foreach ( $settings['entries'] as $index => $entry ) {
				$this->render_entry( $index, $entry, $me, $cache );
			}
			?>
			<p class="ailock-empty" data-ailock-empty<?php echo $settings['entries'] ? ' hidden' : ''; ?>><?php self::the_icon( 'info', 16 ); ?><?php esc_html_e( 'Nothing on the list yet. Add your own address first.', 'admin-ip-lockdown' ); ?></p>
		</div>

		<template data-ailock-template>
			<?php $this->render_entry( '__i__', null, $me, $cache ); ?>
		</template>

		<div class="ailock-type-icons" hidden>
			<?php foreach ( self::TYPE_ICONS as $type => $icon ) : ?>
				<span data-ailock-icon="<?php echo esc_attr( $type ); ?>"><?php self::the_icon( $icon, 16 ); ?></span>
			<?php endforeach; ?>
		</div>

		<div class="ailock-list-actions">
			<button type="button" class="button" data-ailock-add><?php self::the_icon( 'plus', 16 ); ?><?php esc_html_e( 'Add address', 'admin-ip-lockdown' ); ?></button>
			<?php if ( Admin_IP_Lockdown_Access::hosts( $settings ) ) : ?>
				<a class="button" href="<?php echo esc_url( self::action_url( 'dns' ) ); ?>"><?php self::the_icon( 'refresh-cw', 16 ); ?><?php esc_html_e( 'Look hostnames up now', 'admin-ip-lockdown' ); ?></a>
			<?php endif; ?>
		</div>

		<div class="ailock-callout">
			<?php self::the_icon( 'house-wifi', 18 ); ?>
			<span>
				<?php
				printf(
					/* translators: 1: example hostname, 2: list of services. */
					esc_html__( 'Home IP keeps changing? Add a dynamic DNS hostname such as %1$s (free from %2$s). Its current address is let in, and a change is picked up within a minute. Hostnames that resolve to IPv6 let in their whole /64 network.', 'admin-ip-lockdown' ),
					'<code>home.example.duckdns.org</code>',
					'DuckDNS, No-IP, Dynu'
				);
				?>
			</span>
		</div>
		<?php
	}

	/**
	 * One row of the list (or the blank template row).
	 *
	 * @param int|string $index Row index, or "__i__" for the template.
	 * @param array|null $entry Entry, or null for a blank row.
	 * @param string     $me    Visitor's address.
	 * @param array      $cache DNS cache.
	 * @return void
	 */
	private function render_entry( $index, $entry, $me, array $cache ) {
		$base  = self::name( 'entries' ) . '[' . $index . ']';
		$type  = $entry ? $entry['type'] : 'ip';
		$value = $entry ? $entry['value'] : '';
		$label = $entry ? $entry['label'] : '';
		$added = $entry ? $entry['added'] : 0;
		?>
		<div class="ailock-entry" data-ailock-entry>
			<span class="ailock-entry-icon" data-ailock-type-icon title="<?php echo esc_attr( self::type_label( $type ) ); ?>"><?php self::the_icon( self::TYPE_ICONS[ $type ], 16 ); ?></span>
			<input type="text" class="code" name="<?php echo esc_attr( $base . '[value]' ); ?>" value="<?php echo esc_attr( $value ); ?>" placeholder="203.0.113.24" spellcheck="false" autocomplete="off" aria-label="<?php esc_attr_e( 'Address, range or hostname', 'admin-ip-lockdown' ); ?>" data-ailock-value>
			<input type="text" name="<?php echo esc_attr( $base . '[label]' ); ?>" value="<?php echo esc_attr( $label ); ?>" maxlength="60" placeholder="<?php esc_attr_e( 'Label, e.g. Office', 'admin-ip-lockdown' ); ?>" aria-label="<?php esc_attr_e( 'Label', 'admin-ip-lockdown' ); ?>" data-ailock-label>
			<input type="hidden" name="<?php echo esc_attr( $base . '[added]' ); ?>" value="<?php echo esc_attr( (string) $added ); ?>">
			<span class="ailock-entry-status"><?php $this->render_entry_status( $entry, $me, $cache ); ?></span>
			<button type="button" class="button-link ailock-remove" data-ailock-remove aria-label="<?php esc_attr_e( 'Remove', 'admin-ip-lockdown' ); ?>" title="<?php esc_attr_e( 'Remove', 'admin-ip-lockdown' ); ?>"><?php self::the_icon( 'trash-2', 16 ); ?></button>
		</div>
		<?php
	}

	/**
	 * Name of an entry type.
	 *
	 * @param string $type ip, range or host.
	 * @return string
	 */
	private static function type_label( $type ) {
		if ( 'range' === $type ) {
			return __( 'Range', 'admin-ip-lockdown' );
		}

		return 'host' === $type ? __( 'Hostname', 'admin-ip-lockdown' ) : __( 'IP address', 'admin-ip-lockdown' );
	}

	/**
	 * Status column: resolved addresses for hostnames, when it was added
	 * otherwise, and a "You" badge when it lets the current visitor in.
	 *
	 * @param array|null $entry Entry.
	 * @param string     $me    Visitor's address.
	 * @param array      $cache DNS cache.
	 * @return void
	 */
	private function render_entry_status( $entry, $me, array $cache ) {
		if ( ! $entry ) {
			echo '<span class="ailock-muted">' . esc_html__( 'New', 'admin-ip-lockdown' ) . '</span>';
			return;
		}

		if ( 'host' === $entry['type'] ) {
			$info  = isset( $cache[ $entry['value'] ] ) && is_array( $cache[ $entry['value'] ] ) ? $cache[ $entry['value'] ] : array();
			$ips   = isset( $info['ips'] ) && is_array( $info['ips'] ) ? $info['ips'] : array();
			$is_me = Admin_IP_Lockdown_IP::matches_resolved( $me, $ips );

			if ( $is_me ) {
				echo '<span class="ailock-pill is-you">' . esc_html__( 'You', 'admin-ip-lockdown' ) . '</span> ';
			}

			if ( $ips ) {
				echo '<span class="ailock-resolved">' . self::icon( 'arrow-right', 13 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Bundled SVG.

				foreach ( array_slice( $ips, 0, 2 ) as $resolved ) {
					echo '<code>' . esc_html( $resolved ) . '</code>';
				}

				if ( count( $ips ) > 2 ) {
					/* translators: %d: number of further addresses. */
					echo '<span class="ailock-more" title="' . esc_attr( implode( ', ', array_slice( $ips, 2 ) ) ) . '">' . esc_html( sprintf( __( '+%d more', 'admin-ip-lockdown' ), count( $ips ) - 2 ) ) . '</span>';
				}

				echo '</span>';
			}

			if ( ! empty( $info['error'] ) ) {
				echo '<span class="ailock-sub is-error">' . esc_html( $ips ? __( 'Last lookup failed; using the address above', 'admin-ip-lockdown' ) : $info['error'] ) . '</span>';
			} elseif ( ! empty( $info['checked'] ) ) {
				/* translators: %s: time since, e.g. "3 mins". */
				echo '<span class="ailock-sub">' . esc_html( sprintf( __( 'Checked %s ago', 'admin-ip-lockdown' ), human_time_diff( (int) $info['checked'] ) ) ) . '</span>';
			} else {
				echo '<span class="ailock-sub">' . esc_html__( 'Looked up when saved', 'admin-ip-lockdown' ) . '</span>';
			}

			return;
		}

		if ( '' !== $me && Admin_IP_Lockdown_IP::in_range( $me, $entry['value'] ) ) {
			echo '<span class="ailock-pill is-you">' . esc_html__( 'You', 'admin-ip-lockdown' ) . '</span> ';
		}

		if ( $entry['added'] ) {
			/* translators: %s: date. */
			echo '<span class="ailock-sub">' . esc_html( sprintf( __( 'Added %s', 'admin-ip-lockdown' ), wp_date( get_option( 'date_format' ), $entry['added'] ) ) ) . '</span>';
		}
	}

	/**
	 * Allowed IPs: networks unlocked by email link.
	 *
	 * @return void
	 */
	private function render_temporary() {
		?>
		<table class="widefat striped ailock-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Network', 'admin-ip-lockdown' ); ?></th>
					<th><?php esc_html_e( 'Unlocked by', 'admin-ip-lockdown' ); ?></th>
					<th><?php esc_html_e( 'Ends', 'admin-ip-lockdown' ); ?></th>
					<th class="ailock-actions-col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'admin-ip-lockdown' ); ?></span></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( Admin_IP_Lockdown_Access::temporary() as $item ) : ?>
					<?php $user = get_userdata( $item['user'] ); ?>
					<tr>
						<td><code><?php echo esc_html( $item['value'] ); ?></code></td>
						<td><?php echo esc_html( $user ? $user->user_login : '—' ); ?></td>
						<td>
							<?php
							/* translators: %s: time left, e.g. "5 hours". */
							echo esc_html( sprintf( __( 'In %s', 'admin-ip-lockdown' ), human_time_diff( time(), $item['expires'] ) ) );
							?>
						</td>
						<td class="ailock-actions-col">
							<a class="button button-small" href="<?php echo esc_url( self::action_url( 'temp-keep', array( 'value' => $item['value'] ) ) ); ?>"><?php esc_html_e( 'Keep', 'admin-ip-lockdown' ); ?></a>
							<a class="button button-small ailock-danger" href="<?php echo esc_url( self::action_url( 'temp-remove', array( 'value' => $item['value'] ) ) ); ?>" data-ailock-confirm="remove"><?php esc_html_e( 'End now', 'admin-ip-lockdown' ); ?></a>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Allowed IPs: entries from wp-config.php.
	 *
	 * @return void
	 */
	private function render_config() {
		$config = Admin_IP_Lockdown_Access::config_entries( true );
		$me     = Admin_IP_Lockdown_Request::client_ip();
		?>
		<ul class="ailock-chips">
			<?php foreach ( $config['valid'] as $entry ) : ?>
				<?php $is_me = 'host' === $entry['type'] ? Admin_IP_Lockdown_IP::matches_resolved( $me, Admin_IP_Lockdown_DNS::ips( $entry['value'] ) ) : Admin_IP_Lockdown_IP::in_range( $me, $entry['value'] ); ?>
				<li class="ailock-chip"><?php self::the_icon( self::TYPE_ICONS[ $entry['type'] ], 14 ); ?><code><?php echo esc_html( $entry['value'] ); ?></code><?php echo $is_me ? '<span class="ailock-pill is-you">' . esc_html__( 'You', 'admin-ip-lockdown' ) . '</span>' : ''; ?></li>
			<?php endforeach; ?>
			<?php foreach ( $config['invalid'] as $bad ) : ?>
				<li class="ailock-chip is-bad"><?php self::the_icon( 'circle-x', 14 ); ?><code><?php echo esc_html( self::cut( $bad, 60 ) ); ?></code><span><?php esc_html_e( 'not valid, ignored', 'admin-ip-lockdown' ); ?></span></li>
			<?php endforeach; ?>
		</ul>
		<?php
	}

	/**
	 * Protection: what's locked.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_locked( array $settings ) {
		?>
		<div class="ailock-options">
			<?php
			self::option_card( 'checkbox', self::name( 'protect_admin' ), '1', (bool) $settings['protect_admin'], 'layout-dashboard', __( 'The dashboard (wp-admin)', 'admin-ip-lockdown' ), __( 'Every admin screen. admin-ajax.php and admin-post.php stay open, because forms, carts and search on your site use them.', 'admin-ip-lockdown' ) );
			self::option_card( 'checkbox', self::name( 'protect_login' ), '1', (bool) $settings['protect_login'], 'log-in', __( 'The login page (wp-login.php)', 'admin-ip-lockdown' ), __( 'Including registration and password resets. Visitors can still open password-protected posts. Switch off if customers or members sign in on wp-login.php; staff sign-ins stay limited either way.', 'admin-ip-lockdown' ) );
			self::option_card( 'checkbox', self::name( 'protect_xmlrpc' ), '1', (bool) $settings['protect_xmlrpc'], 'code-xml', __( 'XML-RPC (xmlrpc.php)', 'admin-ip-lockdown' ), __( 'An old remote-publishing door that bots love. Leave it open if you use Jetpack, the WordPress mobile app or pingbacks.', 'admin-ip-lockdown' ) );
			?>
		</div>
		<?php
	}

	/**
	 * Protection: staff accounts.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_staff( array $settings ) {
		?>
		<p class="ailock-field-label"><?php esc_html_e( 'Who counts as staff', 'admin-ip-lockdown' ); ?></p>
		<div class="ailock-options">
			<?php
			self::option_card( 'radio', self::name( 'staff' ), 'edit_posts', 'edit_posts' === $settings['staff'], 'users', __( 'Anyone who can write or edit', 'admin-ip-lockdown' ), __( 'Contributors, authors, editors, shop managers and administrators. Customers and subscribers can sign in from anywhere.', 'admin-ip-lockdown' ) );
			self::option_card( 'radio', self::name( 'staff' ), 'manage_options', 'manage_options' === $settings['staff'], 'user-cog', __( 'Administrators only', 'admin-ip-lockdown' ), __( 'Other roles can sign in and keep their sessions from anywhere (wp-admin itself stays locked).', 'admin-ip-lockdown' ) );
			?>
		</div>

		<div class="ailock-settings-list">
			<?php
			self::checkbox( $settings, 'login_guard', __( 'Staff can only sign in from allowed addresses', 'admin-ip-lockdown' ), __( 'On every login form, not just wp-login.php: a shop\'s account page, XML-RPC, custom login forms. The answer is the same whether the password was right or wrong, so it can\'t be used to test passwords.', 'admin-ip-lockdown' ) );
			self::checkbox( $settings, 'session_guard', __( 'Staff sessions only work from allowed addresses', 'admin-ip-lockdown' ), __( 'A login cookie copied from an allowed network is useless anywhere else. Staff browsing your site from another network see it signed out.', 'admin-ip-lockdown' ) );
			self::checkbox( $settings, 'app_passwords', __( 'Application passwords work from any address', 'admin-ip-lockdown' ), __( 'For apps and services that connect with an application password from Users > Profile, such as automation tools and the mobile app. They\'re long random keys, not guessable passwords.', 'admin-ip-lockdown' ) );
			?>
		</div>
		<?php
	}

	/**
	 * Recovery: the unlock email.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_unlock( array $settings ) {
		$admins = Admin_IP_Lockdown_Unlock::eligible_users();
		?>
		<div class="ailock-settings-list">
			<?php self::checkbox( $settings, 'unlock_email', __( 'Show "Email me an unlock link" on the blocked page', 'admin-ip-lockdown' ), __( 'The page answers the same whatever address is typed, so it never reveals who your administrators are. Each address can ask 5 times in 15 minutes, and each account gets at most 3 links an hour.', 'admin-ip-lockdown' ) ); ?>

			<div class="ailock-setting">
				<label class="ailock-inline-field">
					<?php self::the_icon( 'timer', 16 ); ?>
					<span><?php esc_html_e( 'Access from a link lasts', 'admin-ip-lockdown' ); ?></span>
					<select name="<?php echo esc_attr( self::name( 'unlock_hours' ) ); ?>">
						<?php foreach ( Admin_IP_Lockdown_Plugin::UNLOCK_HOURS as $hours ) : ?>
							<option value="<?php echo esc_attr( (string) $hours ); ?>" <?php selected( $hours, $settings['unlock_hours'] ); ?>><?php echo esc_html( Admin_IP_Lockdown_Unlock::duration( $hours ) ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<p class="description"><?php esc_html_e( 'Links themselves work once, within an hour. The network shows under Temporary access, where you can end it early or keep it.', 'admin-ip-lockdown' ); ?></p>
			</div>

			<?php
			/* translators: %s: the site's admin email address. */
			self::checkbox( $settings, 'notify_unlock', sprintf( __( 'Email %s when a link is used', 'admin-ip-lockdown' ), get_option( 'admin_email' ) ), __( 'The site\'s admin address (Settings > General) hears about every unlock, unless it\'s the address that asked for it.', 'admin-ip-lockdown' ) );
			?>
		</div>

		<p class="ailock-field-label"><?php esc_html_e( 'Who can ask for a link', 'admin-ip-lockdown' ); ?></p>
		<?php if ( $admins ) : ?>
			<ul class="ailock-chips">
				<?php foreach ( $admins as $admin ) : ?>
					<li class="ailock-chip"><?php self::the_icon( 'user-round', 14 ); ?><?php echo esc_html( $admin->user_login ); ?></li>
				<?php endforeach; ?>
			</ul>
		<?php endif; ?>
		<p class="description"><?php esc_html_e( 'Administrators, at the email address on their profile. Other staff ask an administrator to add their address.', 'admin-ip-lockdown' ); ?></p>

		<div class="ailock-list-actions">
			<a class="button" href="<?php echo esc_url( self::action_url( 'test-email' ) ); ?>"><?php self::the_icon( 'send', 16 ); ?><?php esc_html_e( 'Send me a test email', 'admin-ip-lockdown' ); ?></a>
			<span class="ailock-muted"><?php esc_html_e( 'Check that this site\'s email reaches you before you need it.', 'admin-ip-lockdown' ); ?></span>
		</div>
		<?php
	}

	/**
	 * Recovery: the blocked page.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_blocked_page( array $settings ) {
		?>
		<p class="ailock-field-label"><label for="ailock-message"><?php esc_html_e( 'Message', 'admin-ip-lockdown' ); ?></label></p>
		<textarea id="ailock-message" class="large-text" rows="3" maxlength="500" name="<?php echo esc_attr( self::name( 'message' ) ); ?>" placeholder="<?php esc_attr_e( 'The admin area of this site can only be reached from approved networks.', 'admin-ip-lockdown' ); ?>"><?php echo esc_textarea( $settings['message'] ); ?></textarea>
		<p class="description"><?php esc_html_e( 'Plain text. Leave empty for the default. For example: "Working remotely? Ask Sam to add your IP."', 'admin-ip-lockdown' ); ?></p>
		<div class="ailock-list-actions">
			<a class="button" href="<?php echo esc_url( self::action_url( 'preview' ) ); ?>" target="_blank" rel="noopener"><?php self::the_icon( 'eye', 16 ); ?><?php esc_html_e( 'Preview the blocked page', 'admin-ip-lockdown' ); ?></a>
			<span class="ailock-muted"><?php esc_html_e( 'Shows the saved version.', 'admin-ip-lockdown' ); ?></span>
		</div>
		<?php
	}

	/**
	 * Recovery: other ways back in.
	 *
	 * @return void
	 */
	private function render_ways() {
		$ways = array(
			array( 'file-cog', __( 'Switch it off in wp-config.php', 'admin-ip-lockdown' ), "define( 'ADMIN_IP_LOCKDOWN_DISABLE', true );", __( 'Add this line above "That\'s all, stop editing!" over FTP or your host\'s file manager. Remove it to switch the lockdown back on.', 'admin-ip-lockdown' ) ),
			array( 'building-2', __( 'Always allow some addresses', 'admin-ip-lockdown' ), "define( 'ADMIN_IP_LOCKDOWN_ALLOW', '203.0.113.24, office.example.com' );", __( 'Addresses, ranges or hostnames that are always let in, separated by commas. Handy for an agency\'s office across every client site.', 'admin-ip-lockdown' ) ),
			array( 'terminal', __( 'WP-CLI', 'admin-ip-lockdown' ), "wp admin-ip-lockdown allow 203.0.113.24\nwp admin-ip-lockdown off", __( 'Over SSH. "status" lists everything that\'s allowed.', 'admin-ip-lockdown' ) ),
			array( 'folder-pen', __( 'Rename the plugin\'s folder', 'admin-ip-lockdown' ), 'wp-content/plugins/admin-ip-lockdown', __( 'WordPress switches a plugin off when its folder goes missing. Rename it back and reactivate it afterwards.', 'admin-ip-lockdown' ) ),
		);
		?>
		<div class="ailock-ways">
			<?php foreach ( $ways as $way ) : ?>
				<div class="ailock-way">
					<span class="ailock-option-icon"><?php self::the_icon( $way[0], 18 ); ?></span>
					<div>
						<strong><?php echo esc_html( $way[1] ); ?></strong>
						<pre><code><?php echo esc_html( $way[2] ); ?></code></pre>
						<span class="ailock-muted"><?php echo esc_html( $way[3] ); ?></span>
					</div>
				</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * IP detection: what this request looks like.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_you( array $settings ) {
		$me       = Admin_IP_Lockdown_Request::resolve( $settings );
		$headers  = Admin_IP_Lockdown_Request::proxy_headers();
		$warnings = array();

		if ( 'direct' === $me['via'] && $headers && ! Admin_IP_Lockdown_IP::is_public( $me['remote'] ) ) {
			$warnings[] = __( 'This request came from a private or local address with proxy headers attached, so a proxy is probably in front of WordPress and every visitor may look like the same address. Add that address under "Other proxy or load balancer" below.', 'admin-ip-lockdown' );
		} elseif ( isset( $headers['CF-Connecting-IP'] ) && ! $me['cloudflare'] ) {
			$warnings[] = $settings['cloudflare']
				? __( 'A CF-Connecting-IP header arrived, but not from Cloudflare\'s network, so it was ignored. That\'s right if someone sent it directly. If your host passes Cloudflare traffic through its own proxy, add that proxy\'s address below.', 'admin-ip-lockdown' )
				: __( 'This request came through Cloudflare, but Cloudflare support is off, so every visitor looks like a Cloudflare server. Switch it on below.', 'admin-ip-lockdown' );
		}

		$via = array(
			'direct'     => __( 'Direct connection', 'admin-ip-lockdown' ),
			'cloudflare' => __( 'Cloudflare', 'admin-ip-lockdown' ),
			'proxy'      => __( 'Your proxy', 'admin-ip-lockdown' ),
		);
		?>
		<dl class="ailock-facts">
			<div><dt><?php esc_html_e( 'Your IP address', 'admin-ip-lockdown' ); ?></dt><dd><code class="ailock-strong-code"><?php echo esc_html( '' !== $me['ip'] ? $me['ip'] : __( 'unknown', 'admin-ip-lockdown' ) ); ?></code></dd></div>
			<div><dt><?php esc_html_e( 'Arrived through', 'admin-ip-lockdown' ); ?></dt><dd><?php echo esc_html( $via[ $me['via'] ] ); ?></dd></div>
			<div><dt><?php esc_html_e( 'Connection from', 'admin-ip-lockdown' ); ?></dt><dd><code><?php echo esc_html( '' !== $me['remote'] ? $me['remote'] : '—' ); ?></code> <span class="ailock-muted">REMOTE_ADDR</span></dd></div>
			<div>
				<dt><?php esc_html_e( 'Proxy headers', 'admin-ip-lockdown' ); ?></dt>
				<dd>
					<?php if ( $headers ) : ?>
						<?php foreach ( $headers as $name => $value ) : ?>
							<span class="ailock-header-line"><span class="ailock-muted"><?php echo esc_html( $name ); ?>:</span> <code><?php echo esc_html( $value ); ?></code></span>
						<?php endforeach; ?>
					<?php else : ?>
						<span class="ailock-muted"><?php esc_html_e( 'None', 'admin-ip-lockdown' ); ?></span>
					<?php endif; ?>
				</dd>
			</div>
		</dl>

		<?php foreach ( $warnings as $warning ) : ?>
			<p class="ailock-callout is-warn"><?php self::the_icon( 'triangle-alert', 18 ); ?><span><?php echo esc_html( $warning ); ?></span></p>
		<?php endforeach; ?>

		<?php if ( ! $warnings ) : ?>
			<p class="ailock-callout is-ok"><?php self::the_icon( 'circle-check', 18 ); ?><span><?php esc_html_e( 'Looks right. Compare the address above with what a "what is my IP" site shows; they should match.', 'admin-ip-lockdown' ); ?></span></p>
		<?php endif; ?>
		<?php
	}

	/**
	 * IP detection: Cloudflare.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_cloudflare( array $settings ) {
		$me      = Admin_IP_Lockdown_Request::resolve( $settings );
		$updated = Admin_IP_Lockdown_Cloudflare::updated();
		$count   = count( Admin_IP_Lockdown_Cloudflare::ranges() );

		self::checkbox( $settings, 'cloudflare', __( 'Use Cloudflare\'s visitor address on requests from Cloudflare', 'admin-ip-lockdown' ), __( 'Safe to leave on even without Cloudflare: the header is ignored on every other request.', 'admin-ip-lockdown' ) );
		?>
		<ul class="ailock-checklist">
			<li class="<?php echo $me['cloudflare'] ? 'is-ok' : 'is-off'; ?>">
				<?php self::the_icon( $me['cloudflare'] ? 'circle-check' : 'circle-dot', 16 ); ?>
				<span><?php echo $me['cloudflare'] ? esc_html__( 'This request came through Cloudflare.', 'admin-ip-lockdown' ) : esc_html__( 'This request didn\'t come through Cloudflare.', 'admin-ip-lockdown' ); ?></span>
			</li>
			<li class="is-ok">
				<?php self::the_icon( 'list-checks', 16 ); ?>
				<span>
					<?php
					echo esc_html(
						$updated
							/* translators: 1: number of ranges, 2: date. */
							? sprintf( __( '%1$d Cloudflare ranges, refreshed from Cloudflare on %2$s.', 'admin-ip-lockdown' ), $count, wp_date( get_option( 'date_format' ), $updated ) )
							/* translators: %d: number of ranges. */
							: sprintf( __( '%d Cloudflare ranges built in, refreshed from Cloudflare weekly.', 'admin-ip-lockdown' ), $count )
					);
					?>
				</span>
			</li>
		</ul>
		<p><a class="button" href="<?php echo esc_url( self::action_url( 'cloudflare' ) ); ?>"><?php self::the_icon( 'refresh-cw', 16 ); ?><?php esc_html_e( 'Refresh the list now', 'admin-ip-lockdown' ); ?></a></p>
		<?php
	}

	/**
	 * IP detection: a custom proxy.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_proxy( array $settings ) {
		$labels = array(
			'x-forwarded-for'   => 'X-Forwarded-For',
			'x-real-ip'         => 'X-Real-IP',
			'true-client-ip'    => 'True-Client-IP',
			'x-sucuri-clientip' => 'X-Sucuri-ClientIP',
		);
		?>
		<p class="ailock-field-label"><label for="ailock-proxies"><?php esc_html_e( 'Your proxies\' addresses', 'admin-ip-lockdown' ); ?></label></p>
		<textarea id="ailock-proxies" class="large-text code" rows="3" name="<?php echo esc_attr( self::name( 'proxies' ) ); ?>" placeholder="10.0.0.0/8" spellcheck="false"><?php echo esc_textarea( implode( "\n", $settings['proxies'] ) ); ?></textarea>
		<p class="description"><?php esc_html_e( 'One address or range per line. Only requests from these addresses are trusted to say who the visitor is; never add a range you don\'t control.', 'admin-ip-lockdown' ); ?></p>

		<label class="ailock-inline-field">
			<span><?php esc_html_e( 'They pass the visitor\'s address in', 'admin-ip-lockdown' ); ?></span>
			<select name="<?php echo esc_attr( self::name( 'proxy_header' ) ); ?>">
				<?php foreach ( $labels as $key => $label ) : ?>
					<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $key, $settings['proxy_header'] ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
		</label>
		<p class="description"><?php esc_html_e( 'X-Forwarded-For is read right to left, skipping your own proxies, so addresses a visitor adds to it are never used.', 'admin-ip-lockdown' ); ?></p>
		<?php
	}

	/**
	 * Activity: headline numbers.
	 *
	 * @return void
	 */
	private function render_overview() {
		$stats = Admin_IP_Lockdown_Log::stats();
		$tiles = array(
			array( 'ban', $stats['today'], __( 'Blocked today', 'admin-ip-lockdown' ) ),
			array( 'calendar-clock', $stats['week'], __( 'Blocked in 7 days', 'admin-ip-lockdown' ) ),
			array( 'globe', $stats['ips'], __( 'Addresses in 7 days', 'admin-ip-lockdown' ) ),
			array( 'mail-check', $stats['unlocks'], __( 'Unlocks in 30 days', 'admin-ip-lockdown' ) ),
		);
		?>
		<div class="ailock-stats">
			<?php foreach ( $tiles as $tile ) : ?>
				<div class="ailock-stat">
					<span class="ailock-stat-icon"><?php self::the_icon( $tile[0], 18 ); ?></span>
					<span class="ailock-stat-num"><?php echo esc_html( number_format_i18n( $tile[1] ) ); ?></span>
					<span class="ailock-stat-label"><?php echo esc_html( $tile[2] ); ?></span>
				</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Name of a blocked-attempt kind.
	 *
	 * @param string $kind Kind.
	 * @return string
	 */
	private static function kind_label( $kind ) {
		switch ( $kind ) {
			case 'login':
				return __( 'Login page', 'admin-ip-lockdown' );
			case 'admin':
				return __( 'wp-admin', 'admin-ip-lockdown' );
			case 'xmlrpc':
				return __( 'XML-RPC', 'admin-ip-lockdown' );
			case 'signin':
				return __( 'Staff sign-in', 'admin-ip-lockdown' );
		}

		return __( 'Staff session', 'admin-ip-lockdown' );
	}

	/**
	 * Activity: recently blocked addresses.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_blocked( array $settings ) {
		$rows = Admin_IP_Lockdown_Log::recent( 25 );

		if ( ! $rows ) {
			echo '<p class="ailock-empty">' . self::icon( 'shield-check', 16 ) . esc_html( $settings['log'] ? __( 'Nothing blocked in the last 7 days.', 'admin-ip-lockdown' ) : __( 'Logging is off.', 'admin-ip-lockdown' ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Bundled SVG.
			return;
		}
		?>
		<table class="widefat striped ailock-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Address', 'admin-ip-lockdown' ); ?></th>
					<th><?php esc_html_e( 'Tried', 'admin-ip-lockdown' ); ?></th>
					<th class="num"><?php esc_html_e( 'Attempts', 'admin-ip-lockdown' ); ?></th>
					<th><?php esc_html_e( 'Last seen', 'admin-ip-lockdown' ); ?></th>
					<th class="ailock-actions-col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'admin-ip-lockdown' ); ?></span></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $rows as $row ) : ?>
					<?php $seen = strtotime( $row['last_seen'] . ' UTC' ); ?>
					<tr>
						<td><code><?php echo esc_html( $row['ip'] ); ?></code></td>
						<td>
							<?php foreach ( $row['kinds'] as $kind ) : ?>
								<span class="ailock-pill is-<?php echo esc_attr( $kind ); ?>"><?php echo esc_html( self::kind_label( $kind ) ); ?></span>
							<?php endforeach; ?>
							<?php if ( '' !== $row['path'] ) : ?>
								<span class="ailock-sub"><?php echo esc_html( $row['path'] ); ?></span>
							<?php endif; ?>
						</td>
						<td class="num"><?php echo esc_html( number_format_i18n( $row['hits'] ) ); ?></td>
						<td>
							<?php
							/* translators: %s: time since, e.g. "5 mins". */
							echo esc_html( $seen ? sprintf( __( '%s ago', 'admin-ip-lockdown' ), human_time_diff( $seen ) ) : '' );
							?>
						</td>
						<td class="ailock-actions-col"><a class="button button-small" href="<?php echo esc_url( self::action_url( 'allow', array( 'value' => $row['ip'] ) ) ); ?>"><?php esc_html_e( 'Allow', 'admin-ip-lockdown' ); ?></a></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Activity: unlock-link events.
	 *
	 * @return void
	 */
	private function render_events() {
		$events = array_reverse( Admin_IP_Lockdown_Log::events() );
		$names  = array(
			'requested' => array( 'mail', __( 'Link sent', 'admin-ip-lockdown' ) ),
			'used'      => array( 'lock-open', __( 'Link used', 'admin-ip-lockdown' ) ),
			'removed'   => array( 'timer-off', __( 'Access ended early', 'admin-ip-lockdown' ) ),
			'kept'      => array( 'list-plus', __( 'Moved to the list', 'admin-ip-lockdown' ) ),
			'test'      => array( 'send', __( 'Test email', 'admin-ip-lockdown' ) ),
		);

		if ( ! $events ) {
			echo '<p class="ailock-empty">' . self::icon( 'mail', 16 ) . esc_html__( 'No unlock links have been asked for yet.', 'admin-ip-lockdown' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Bundled SVG.
			return;
		}
		?>
		<table class="widefat striped ailock-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'What', 'admin-ip-lockdown' ); ?></th>
					<th><?php esc_html_e( 'Account', 'admin-ip-lockdown' ); ?></th>
					<th><?php esc_html_e( 'Address', 'admin-ip-lockdown' ); ?></th>
					<th><?php esc_html_e( 'When', 'admin-ip-lockdown' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( array_slice( $events, 0, 15 ) as $event ) : ?>
					<?php
					$name = isset( $names[ $event['type'] ] ) ? $names[ $event['type'] ] : array( 'circle-dot', $event['type'] );
					$user = $event['user'] ? get_userdata( $event['user'] ) : false;
					?>
					<tr>
						<td><span class="ailock-event"><?php self::the_icon( $name[0], 15 ); ?><?php echo esc_html( $name[1] ); ?></span></td>
						<td><?php echo esc_html( $user ? $user->user_login : '—' ); ?></td>
						<td><code><?php echo esc_html( '' !== $event['ip'] ? $event['ip'] : '—' ); ?></code></td>
						<td>
							<?php
							/* translators: %s: time since, e.g. "5 mins". */
							echo esc_html( sprintf( __( '%s ago', 'admin-ip-lockdown' ), human_time_diff( $event['time'] ) ) );
							?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Activity: logging settings.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_logging( array $settings ) {
		self::checkbox( $settings, 'log', __( 'Keep a 30-day log of blocked attempts', 'admin-ip-lockdown' ), __( 'One row per address per day, with a count, in its own small table. The address and the page asked for are kept, never query strings.', 'admin-ip-lockdown' ) );
		?>
		<div class="ailock-list-actions">
			<a class="button ailock-danger" href="<?php echo esc_url( self::action_url( 'clear' ) ); ?>" data-ailock-confirm="clear"><?php self::the_icon( 'trash-2', 16 ); ?><?php esc_html_e( 'Clear activity', 'admin-ip-lockdown' ); ?></a>
		</div>
		<?php
	}

	/**
	 * The sidebar: save, status, how it works, updates.
	 *
	 * @param array $settings Settings.
	 * @return void
	 */
	private function render_sidebar( array $settings ) {
		$me     = Admin_IP_Lockdown_Request::client_ip();
		$hosts  = count( Admin_IP_Lockdown_Access::hosts( $settings ) );
		$count  = count( $settings['entries'] ) + count( Admin_IP_Lockdown_Access::config_entries() );
		$on     = Admin_IP_Lockdown_Plugin::enforcing();
		$listed = null !== Admin_IP_Lockdown_Access::match( $me, $settings );

		$status = array(
			array( $on, $on ? __( 'Lockdown is on', 'admin-ip-lockdown' ) : __( 'Lockdown is off', 'admin-ip-lockdown' ) ),
			array( $listed, $listed ? __( 'Your IP address is allowed', 'admin-ip-lockdown' ) : __( 'Your IP address isn\'t on the list', 'admin-ip-lockdown' ) ),
			array(
				$count > 0,
				/* translators: %d: number of entries on the allowed list. */
				sprintf( _n( '%d allowed entry', '%d allowed entries', $count, 'admin-ip-lockdown' ), $count )
				/* translators: %d: number of hostnames among them. */
				. ( $hosts ? ', ' . sprintf( _n( '%d hostname', '%d hostnames', $hosts, 'admin-ip-lockdown' ), $hosts ) : '' ),
			),
			array( (bool) $settings['protect_login'], $settings['protect_login'] ? __( 'Login page locked', 'admin-ip-lockdown' ) : __( 'Login page open', 'admin-ip-lockdown' ) ),
			array( (bool) $settings['login_guard'], $settings['login_guard'] ? __( 'Staff sign-ins limited everywhere', 'admin-ip-lockdown' ) : __( 'Staff can sign in from other forms', 'admin-ip-lockdown' ) ),
			array( (bool) $settings['unlock_email'], $settings['unlock_email'] ? __( 'Emergency unlock email on', 'admin-ip-lockdown' ) : __( 'Emergency unlock email off', 'admin-ip-lockdown' ) ),
		);

		$steps = array(
			array( 'log-in', __( 'Someone opens wp-admin or the login page.', 'admin-ip-lockdown' ) ),
			array( 'list-checks', __( 'Their IP is checked against your list, your hostnames and any unlocked networks.', 'admin-ip-lockdown' ) ),
			array( 'shield-ban', __( 'Not on it? They get "Access restricted" and never see a login form.', 'admin-ip-lockdown' ) ),
		);
		?>
		<div class="postbox ailock-save-box">
			<div class="postbox-header">
				<h2 class="hndle">
					<?php self::the_icon( 'save' ); ?>
					<?php esc_html_e( 'Save', 'admin-ip-lockdown' ); ?>
				</h2>
			</div>
			<div class="inside">
				<p><?php esc_html_e( 'Settings on every tab are saved together. Your own address is checked first, so a save can\'t lock you out.', 'admin-ip-lockdown' ); ?></p>
				<?php submit_button( __( 'Save Changes', 'admin-ip-lockdown' ), 'primary large', 'submit', false ); ?>
			</div>
		</div>

		<div class="postbox">
			<div class="postbox-header">
				<h2 class="hndle">
					<?php self::the_icon( 'activity' ); ?>
					<?php esc_html_e( 'Status', 'admin-ip-lockdown' ); ?>
				</h2>
			</div>
			<div class="inside">
				<ul class="ailock-checklist">
					<?php foreach ( $status as $item ) : ?>
						<li class="<?php echo $item[0] ? 'is-ok' : 'is-off'; ?>"><?php self::the_icon( $item[0] ? 'circle-check' : 'circle-dot', 16 ); ?><span><?php echo esc_html( $item[1] ); ?></span></li>
					<?php endforeach; ?>
				</ul>
			</div>
		</div>

		<div class="postbox">
			<div class="postbox-header">
				<h2 class="hndle">
					<?php self::the_icon( 'lightbulb' ); ?>
					<?php esc_html_e( 'How it works', 'admin-ip-lockdown' ); ?>
				</h2>
			</div>
			<div class="inside">
				<ol class="ailock-steps">
					<?php foreach ( $steps as $step ) : ?>
						<li><span class="ailock-step-icon"><?php self::the_icon( $step[0], 16 ); ?></span><span><?php echo esc_html( $step[1] ); ?></span></li>
					<?php endforeach; ?>
				</ol>
				<p class="ailock-muted"><?php esc_html_e( 'Locked out on the road? The blocked page can email an administrator a one-time unlock link.', 'admin-ip-lockdown' ); ?></p>
			</div>
		</div>

		<?php
		$this->render_updates_box();
	}

	/**
	 * Show where updates come from, so it's easy to confirm the repo is wired up.
	 *
	 * @return void
	 */
	private function render_updates_box() {
		$repo_label = preg_replace( '#^https?://[^/]+/#', '', untrailingslashit( ADMIN_IP_LOCKDOWN_REPO ) );
		$check_url  = Admin_IP_Lockdown_Updater::check_now_url();
		?>
		<div class="postbox ailock-updates-box">
			<div class="postbox-header">
				<h2 class="hndle">
					<?php self::the_icon( 'refresh-cw' ); ?>
					<?php esc_html_e( 'Updates', 'admin-ip-lockdown' ); ?>
				</h2>
			</div>
			<div class="inside">
				<p>
					<?php
					/* translators: %s: installed plugin version. */
					printf( esc_html__( 'Installed version: %s', 'admin-ip-lockdown' ), '<strong>' . esc_html( ADMIN_IP_LOCKDOWN_VERSION ) . '</strong>' );
					?>
				</p>

				<?php if ( ! Admin_IP_Lockdown_Updater::has_repo() ) : ?>
					<p>
						<?php
						printf(
							/* translators: 1: header name, 2: main plugin file. */
							esc_html__( 'No repo set. Add it to the %1$s header in %2$s to turn on automatic updates.', 'admin-ip-lockdown' ),
							'<code>Update URI</code>',
							'<code>' . esc_html( plugin_basename( ADMIN_IP_LOCKDOWN_FILE ) ) . '</code>'
						);
						?>
					</p>
				<?php elseif ( Admin_IP_Lockdown_Updater::is_dev_copy() ) : ?>
					<p>
						<?php
						printf(
							/* translators: 1: repo, 2: constant name. */
							esc_html__( 'Releases come from %1$s, but update checks are off on this development copy so an update can\'t overwrite your work. Define %2$s as false in wp-config.php to test updates here.', 'admin-ip-lockdown' ),
							'<a href="' . esc_url( ADMIN_IP_LOCKDOWN_REPO ) . '" target="_blank" rel="noopener">' . esc_html( $repo_label ) . '</a>',
							'<code>ADMIN_IP_LOCKDOWN_DEV_MODE</code>'
						);
						?>
					</p>
				<?php else : ?>
					<p>
						<?php
						printf(
							/* translators: %s: repo. */
							esc_html__( 'Updates come from the latest release of %s.', 'admin-ip-lockdown' ),
							'<a href="' . esc_url( ADMIN_IP_LOCKDOWN_REPO ) . '" target="_blank" rel="noopener">' . esc_html( $repo_label ) . '</a>'
						);
						?>
					</p>
					<?php if ( $check_url ) : ?>
						<p><a class="button" href="<?php echo esc_url( $check_url ); ?>"><?php esc_html_e( 'Check for updates', 'admin-ip-lockdown' ); ?></a></p>
					<?php endif; ?>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}
}
