<?php
/**
 * The pages people see instead of wp-admin or the login screen: "Access
 * restricted" (with the unlock-link form) and the unlock link's own pages.
 *
 * They're standalone pages: no theme, no scripts, no outside requests, and
 * a strict Content-Security-Policy. The only visitor detail shown is their
 * own IP address, which they need to get it added.
 *
 * @package Admin_IP_Lockdown
 */

defined( 'ABSPATH' ) || exit;

/**
 * Blocked and unlock pages.
 */
final class Admin_IP_Lockdown_Blocked {

	/**
	 * Show the "Access restricted" page and stop. Handles the unlock-link
	 * form when it's posted.
	 *
	 * @param string $ip      Visitor's address.
	 * @param bool   $preview Admin preview from the settings page.
	 * @return void
	 */
	public static function render( $ip, $preview = false ) {
		$settings = Admin_IP_Lockdown_Plugin::settings();
		$notice   = '';
		$form     = (bool) $settings['unlock_email'];

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Public form; abuse is rate limited per address and per account.
		if ( $form && ! $preview && 'POST' === Admin_IP_Lockdown_Request::server( 'REQUEST_METHOD' ) && isset( $_POST['ailock_request'], $_POST['ailock_email'] ) && is_string( $_POST['ailock_email'] ) ) {
			$result = Admin_IP_Lockdown_Unlock::request( wp_unslash( $_POST['ailock_email'] ), $ip ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Missing -- Sanitized in request().

			$notice = 'limited' === $result
				? '<p class="notice is-error">' . esc_html__( 'Too many requests from your network. Please wait 15 minutes and try again.', 'admin-ip-lockdown' ) . '</p>'
				: '<p class="notice is-ok">' . esc_html__( 'If that address belongs to an administrator of this site, an unlock link is on its way. It works for one hour. Check your spam folder too.', 'admin-ip-lockdown' ) . '</p>';
			$form   = false;
		}

		$message = trim( $settings['message'] );

		if ( '' === $message ) {
			$message = __( 'The admin area of this site can only be reached from approved networks.', 'admin-ip-lockdown' );
		}

		ob_start();
		?>
		<div class="icon"><?php echo self::icon( 'lock' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fixed SVG. ?></div>
		<h1><?php esc_html_e( 'Access restricted', 'admin-ip-lockdown' ); ?></h1>
		<p><?php echo nl2br( esc_html( $message ) ); ?></p>
		<p class="ip">
			<?php esc_html_e( 'Your IP address', 'admin-ip-lockdown' ); ?>
			<code><?php echo esc_html( '' !== $ip ? $ip : __( 'unknown', 'admin-ip-lockdown' ) ); ?></code>
		</p>
		<?php
		echo $notice; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Built from escaped strings above.

		if ( $form ) :
			?>
			<details class="unlock"<?php echo $preview ? ' open' : ''; ?>>
				<summary><?php esc_html_e( 'Administrator? Email me an unlock link', 'admin-ip-lockdown' ); ?></summary>
				<form method="post">
					<label for="ailock-email"><?php esc_html_e( 'Your account\'s email address', 'admin-ip-lockdown' ); ?></label>
					<input type="email" id="ailock-email" name="ailock_email" required maxlength="254" autocomplete="email"<?php disabled( $preview ); ?>>
					<input type="hidden" name="ailock_request" value="1">
					<button type="submit"<?php disabled( $preview ); ?>><?php esc_html_e( 'Email me an unlock link', 'admin-ip-lockdown' ); ?></button>
					<p class="small"><?php esc_html_e( 'The link lets in the network you open it from, for a limited time.', 'admin-ip-lockdown' ); ?></p>
				</form>
			</details>
			<?php
		endif;

		self::output( __( 'Access restricted', 'admin-ip-lockdown' ), ob_get_clean(), $preview ? 200 : 403, $preview );
	}

	/**
	 * Show one of the unlock link's pages and stop.
	 *
	 * @param string $state    confirm, already or invalid.
	 * @param string $ip       Visitor's address.
	 * @param string $duration How long access would last, in words (confirm).
	 * @return void
	 */
	public static function render_unlock( $state, $ip, $duration = '' ) {
		ob_start();

		if ( 'confirm' === $state ) :
			?>
			<div class="icon is-blue"><?php echo self::icon( 'lock-open' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fixed SVG. ?></div>
			<h1><?php esc_html_e( 'Unlock the admin area', 'admin-ip-lockdown' ); ?></h1>
			<p>
				<?php
				printf(
					/* translators: 1: IP address, 2: length of time, e.g. "24 hours". */
					esc_html__( 'This lets %1$s reach the admin area and login page for %2$s. You\'ll still need to sign in.', 'admin-ip-lockdown' ),
					'<code>' . esc_html( $ip ) . '</code>',
					esc_html( $duration )
				);
				?>
			</p>
			<form method="post">
				<input type="hidden" name="ailock_confirm" value="1">
				<button type="submit"><?php esc_html_e( 'Unlock access', 'admin-ip-lockdown' ); ?></button>
			</form>
			<?php
		elseif ( 'already' === $state ) :
			?>
			<div class="icon is-ok"><?php echo self::icon( 'circle-check' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fixed SVG. ?></div>
			<h1><?php esc_html_e( 'You already have access', 'admin-ip-lockdown' ); ?></h1>
			<p><?php esc_html_e( 'Your network can already reach the admin area, so this link wasn\'t needed. It has been left unused.', 'admin-ip-lockdown' ); ?></p>
			<p><a class="button" href="<?php echo esc_url( admin_url() ); ?>"><?php esc_html_e( 'Go to the dashboard', 'admin-ip-lockdown' ); ?></a></p>
			<?php
		else :
			?>
			<div class="icon"><?php echo self::icon( 'link-2-off' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fixed SVG. ?></div>
			<h1><?php esc_html_e( 'This link can\'t be used', 'admin-ip-lockdown' ); ?></h1>
			<p><?php esc_html_e( 'It has expired or was already used. Unlock links work once, for one hour. Ask for a new one from the page you see when you try to sign in.', 'admin-ip-lockdown' ); ?></p>
			<?php
		endif;

		self::output( __( 'Unlock the admin area', 'admin-ip-lockdown' ), ob_get_clean(), 'invalid' === $state ? 403 : 200 );
	}

	/**
	 * An icon from the plugin's set, styled for these pages.
	 *
	 * @param string $name Lucide icon.
	 * @return string
	 */
	private static function icon( $name ) {
		return Admin_IP_Lockdown_Icons::get( $name, 28 );
	}

	/**
	 * Send the page and stop.
	 *
	 * @param string $title   Page title.
	 * @param string $body    Inner HTML (escaped by the caller).
	 * @param int    $status  HTTP status.
	 * @param bool   $preview Admin preview from the settings page (adds a banner).
	 * @return void
	 */
	private static function output( $title, $body, $status, $preview = false ) {
		if ( ! headers_sent() ) {
			status_header( $status );
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'X-Robots-Tag: noindex, nofollow' );
			header( 'Referrer-Policy: no-referrer' );
			header( 'X-Frame-Options: DENY' );
			header( 'X-Content-Type-Options: nosniff' );
			header( "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" );
		}

		$site = Admin_IP_Lockdown_Unlock::site_name();
		$lang = get_bloginfo( 'language' );

		?>
<!DOCTYPE html>
<html lang="<?php echo esc_attr( $lang ? $lang : 'en' ); ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?php echo esc_html( $title . ' | ' . $site ); ?></title>
<style>
*,*::before,*::after{box-sizing:border-box}
html{background:#f0f0f1}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 16px;color:#1d2327;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif}
.card{width:100%;max-width:440px;padding:36px 32px 30px;background:#fff;border:1px solid #dcdcde;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.04);text-align:center}
.icon{display:inline-flex;align-items:center;justify-content:center;width:60px;height:60px;margin-bottom:14px;border-radius:50%;background:#fcf0f1;color:#b32d2e}
.icon.is-blue{background:#f0f6fc;color:#2271b1}
.icon.is-ok{background:#edfaef;color:#008a20}
.icon svg{display:block}
h1{margin:0 0 10px;font-size:22px;line-height:1.3;font-weight:600}
p{margin:0 0 14px;color:#50575e}
.ip{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:8px;margin:18px 0;font-size:13px;color:#646970}
code{padding:3px 8px;border-radius:5px;background:#f0f0f1;color:#1d2327;font:600 14px/1.5 Menlo,Consolas,monospace;word-break:break-all}
.unlock{margin-top:18px;padding-top:16px;border-top:1px solid #f0f0f1;text-align:left}
summary{cursor:pointer;color:#2271b1;font-weight:600;text-align:center;list-style-position:inside}
form{margin-top:14px;text-align:left}
label{display:block;margin-bottom:6px;font-size:14px;font-weight:600}
input[type=email]{width:100%;padding:9px 12px;border:1px solid #8c8f94;border-radius:5px;font:inherit}
input[type=email]:focus{border-color:#2271b1;outline:2px solid transparent;box-shadow:0 0 0 1px #2271b1}
button:disabled,input:disabled{opacity:.6;cursor:not-allowed}
button,.button{display:inline-block;width:100%;margin-top:12px;padding:10px 16px;border:0;border-radius:5px;background:#2271b1;color:#fff;font:600 15px/1.4 inherit;font-family:inherit;text-align:center;text-decoration:none;cursor:pointer}
button:hover,.button:hover{background:#135e96}
.small{margin:10px 0 0;font-size:13px;color:#646970;text-align:center}
.notice{padding:10px 12px;border-left:4px solid;border-radius:0 5px 5px 0;text-align:left;font-size:14px}
.notice.is-ok{border-color:#00a32a;background:#edfaef;color:#1d2327}
.notice.is-error{border-color:#d63638;background:#fcf0f1;color:#1d2327}
.site{margin-top:18px;font-size:13px;color:#8c8f94}
		<?php if ( $preview ) : ?>
.preview{position:fixed;top:0;left:0;right:0;padding:8px 16px;background:#1d2327;color:#fff;font-size:13px;text-align:center}
		<?php endif; ?>
</style>
</head>
<body>
		<?php if ( $preview ) : ?>
<div class="preview"><?php esc_html_e( 'Preview: this is what blocked visitors see. The form is disabled here.', 'admin-ip-lockdown' ); ?></div>
		<?php endif; ?>
<main class="card">
		<?php echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by the caller. ?>
</main>
<p class="site"><?php echo esc_html( $site ); ?></p>
</body>
</html>
		<?php
		exit;
	}
}
