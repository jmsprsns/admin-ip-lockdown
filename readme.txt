=== Admin IP Lockdown ===
Contributors: contentpowered
Author: Content Powered
Author URI: https://www.contentpowered.com/wordpress-plugins/
Plugin URI: https://www.contentpowered.com
Tags: security, ip whitelist, login protection, wp-admin, cloudflare
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.2
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restricts wp-admin and wp-login.php to allowed IP addresses, with Cloudflare support, dynamic DNS hostnames for home IPs that change, and an emergency email unlock link so you can't lock yourself out.

== Description ==

Most attacks on a WordPress site go through its login page: password guessing, stolen passwords, bots hammering wp-login.php all day. If only you and your team ever sign in, there's no reason the rest of the internet should even see that page.

Admin IP Lockdown only lets wp-admin and the login page open for the addresses you list. Everyone else gets a short "Access restricted" page and never sees a login form.

= What you can allow =

* **IP addresses**, IPv4 or IPv6.
* **Ranges**, written as 203.0.113.0/24 or 203.0.113.*.
* **Dynamic DNS hostnames** such as home.example.duckdns.org, for a home connection whose IP changes. The hostname's current address is let in, and a change is picked up within a minute. Hostnames that resolve to IPv6 let in their whole /64 network, since every device at home gets its own IPv6 address.

Your own address is added when you activate the plugin, and the lockdown stays off until you switch it on.

= You can't lock yourself out =

* Every save checks your own address first. A change that would shut you out isn't saved.
* **Emergency unlock email**: locked out on a new network? On the "Access restricted" page, enter your administrator email address and get a one-time link. It lets in the network you open it from for 24 hours (you choose how long). The link works once, runs out after an hour, and needs a button press, so email scanners that open links can't use it up.
* The site's admin email address hears about every unlock.
* No email? Add one line to wp-config.php, use WP-CLI, or rename the plugin's folder. The settings page lists all of these.

= Cloudflare-aware =

Behind Cloudflare, every request arrives from a Cloudflare server. The plugin uses Cloudflare's visitor address header, but only on requests that really come from Cloudflare's network, so it can't be faked by sending the header directly. Cloudflare's address list is built in and refreshed weekly. Another proxy, load balancer or firewall (such as Sucuri) can be set up too.

= Closes the other ways in =

Locking wp-login.php alone leaves other doors open, so staff accounts get two more protections:

* **Staff can only sign in from allowed addresses**, through any login form: a shop's account page, XML-RPC or custom login forms. The answer is the same whether the password was right or wrong, so it can't be used to test passwords.
* **Staff sessions only work from allowed addresses**, so a login cookie copied from an allowed network is useless anywhere else.

You choose who counts as staff: anyone who can write or edit, or administrators only. Customers and subscribers can still sign in from anywhere. Application passwords for apps and integrations can keep working from any address.

= Also =

* Optional XML-RPC lock.
* admin-ajax.php and admin-post.php stay open, because forms, carts and search on your site use them.
* Activity tab: what was blocked in the last 7 days, from where, and every unlock link sent and used. One row per address per day, kept for 30 days, never with query strings.
* An "Allow" button beside each blocked address, for the colleague who just got turned away.
* `ADMIN_IP_LOCKDOWN_ALLOW` in wp-config.php always lets in an address, range or hostname: handy for an agency's office IP across every client site.
* The site's own loopback requests (Site Health, the file editor's safety check) are signed and let through.
* WP-CLI: `wp admin-ip-lockdown status`, `allow`, `remove`, `on`, `off`.

Find it under Content Powered > Admin IP Lockdown in the admin menu.

Found a bug or have an idea? Use Content Powered > Report a Bug or Content Powered > Submit Feedback to send it straight to us.

= Credits =

* Icons by [Lucide](https://lucide.dev), used under the ISC License. Icons derived from [Feather](https://feathericons.com) are under the MIT License. The full license text is in `icons/LICENSE`.
* Updates delivered by [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker) by Janis Elsts, MIT License.

== Installation ==

1. Upload the `admin-ip-lockdown` folder to `/wp-content/plugins/`.
2. Activate the plugin through the Plugins screen in WordPress. Your current IP address is put on the allowed list.
3. Go to Content Powered > Admin IP Lockdown, add any other addresses (office, home hostname, colleagues), then switch the lockdown on and save.
4. On the Recovery tab, send yourself a test email so you know unlock links will arrive.

Updates arrive through the normal WordPress Updates screen, and you can turn on auto-updates from the Plugins screen.

== Frequently Asked Questions ==

= I'm locked out. How do I get back in? =

On the "Access restricted" page, open "Administrator? Email me an unlock link" and enter your account's email address. If email doesn't work, add `define( 'ADMIN_IP_LOCKDOWN_DISABLE', true );` to wp-config.php, run `wp admin-ip-lockdown off`, or rename the plugin's folder over FTP.

= My home IP changes all the time. =

Set up a free dynamic DNS hostname (DuckDNS, No-IP, Dynu and others; many routers can keep one updated) and add the hostname instead of the IP.

= Does it work behind Cloudflare? =

Yes, with nothing to set up. The IP detection tab shows which address the site sees for you and how it got it.

= Will customers still be able to sign in to my shop? =

Yes. Customers sign in on the shop's account page, which isn't locked, and only staff accounts are limited to allowed addresses. If customers or members sign in on wp-login.php itself, switch off "The login page" on the Protection tab; staff sign-ins stay limited either way.

= Does it break Jetpack, the mobile app or other integrations? =

XML-RPC is left open unless you lock it. Application passwords work from any address unless you switch that off.

= What does it store? =

Your settings, a cache of what your hostnames point to, networks unlocked by email link while their access lasts, and a log of blocked attempts (address, page, count) kept for 30 days. Deleting the plugin removes all of it.

== Changelog ==

See https://github.com/jmsprsns/admin-ip-lockdown/releases for the full release history.
