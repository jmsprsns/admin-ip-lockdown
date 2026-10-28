# Admin IP Lockdown

Restricts wp-admin and wp-login.php to allowed IP addresses, with Cloudflare support, dynamic DNS hostnames for home IPs that change, and an emergency email unlock link so you can't lock yourself out.

By [Content Powered](https://www.contentpowered.com/wordpress-plugins/).

## What it does

- **Allowed list**: IPv4 and IPv6 addresses, ranges (`203.0.113.0/24`, `203.0.113.*`) and dynamic DNS hostnames. Everyone else gets an "Access restricted" page (HTTP 403) instead of wp-admin or wp-login.php.
- **Hostnames** are looked up when saved and cached. Normal requests never trigger a lookup; when someone is about to be blocked, hostnames are looked up again at most once a minute site-wide, so a changed home IP works within a minute. A failed lookup keeps the last good addresses. IPv6 results allow their /64.
- **Cloudflare**: `CF-Connecting-IP` is used only when `REMOTE_ADDR` is in Cloudflare's published ranges (built in, refreshed weekly from Cloudflare's API, only ever added to). `CF-Connecting-IPv6` is read only in Pseudo IPv4 "Overwrite headers" mode (`CF-Connecting-IP` in 240.0.0.0/4). Other proxies: list their addresses and pick the header; `X-Forwarded-For` is walked right to left past trusted hops, and a malformed entry stops the walk (fails closed).
- **Staff accounts** (anyone with `edit_posts`, or administrators only): sign-ins through any form (`authenticate` filter) and sessions (`determine_current_user`) only count from allowed addresses. The sign-in refusal is the same whether the password was right or not. Application passwords can be exempted.
- **Emergency unlock email** on the blocked page, for administrators: 48-hex-character token stored as an HMAC, one hour, single use, confirmed with a POST (link scanners can't spend it). The same reply for every address entered; mail goes out after the response is flushed. 5 requests per IP per 15 minutes, 3 links per account per hour. Access goes to the network the link is opened from (IPv6: its /64) for 1 hour to 7 days, and the site admin email is told.
- **Can't lock yourself out**: a save that wouldn't allow the person saving it is refused; the temporary access you're using can't be ended from the page; with nothing on any list the lockdown doesn't run.
- **Never applies to** WP-CLI, WP-Cron, admin-ajax.php, admin-post.php, or the site's own loopback requests made during an administrator's page load (signed with an HMAC of a 5-minute window, sent only to the site's own host).
- **Activity**: one row per address per day in `{prefix}ailock_log` (path without query string, kinds, count), 30 days, at most 100,000 rows.

### wp-config.php

```php
define( 'ADMIN_IP_LOCKDOWN_DISABLE', true );                              // Switch the lockdown off.
define( 'ADMIN_IP_LOCKDOWN_ALLOW', '203.0.113.24, office.example.com' );  // Always allowed.
```

### WP-CLI

```bash
wp admin-ip-lockdown status
wp admin-ip-lockdown allow 203.0.113.24 --label="Office"
wp admin-ip-lockdown remove 203.0.113.24
wp admin-ip-lockdown on
wp admin-ip-lockdown off
```

## Automatic updates

Updates come from https://github.com/jmsprsns/admin-ip-lockdown through the bundled [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker) (PUC). Every 12 hours each site checks the repo's latest GitHub release. When there's a newer version, it appears in Dashboard > Updates like any other plugin, with one-click updates and auto-updates.

The repo URL is the `Update URI` header in `admin-ip-lockdown.php`. That header also stops WordPress.org from offering a same-slug plugin as an "update" that would overwrite this one.

### Releasing an update

1. Bump `Version:` in the `admin-ip-lockdown.php` header. It's the only place the version lives.
2. Commit and push to `main`.
3. Publish a release whose tag matches that version:

   ```bash
   gh release create v1.0.1 --title 1.0.1 --generate-notes
   ```

Sites pick it up on their next check. To check right away, use "Check for updates" on the plugin's row in the Plugins screen, or the button on its settings page. The release notes become the changelog in the "View details" popup. The description, requirements and "Tested up to" come from `readme.txt`.

If the tag and the `Version:` header disagree, sites will keep being offered the same update, so bump the header before you tag.

If a repo has no releases, PUC falls back to the highest version tag, then to the `Version:` header on `main`.

### Development copies

Installing an update replaces the whole plugin folder, so update checks are off in any copy with a `.git` folder. That stops an update from wiping your working tree. To test updates in a checkout anyway, or to turn them off somewhere without git, add this to `wp-config.php`:

```php
define( 'ADMIN_IP_LOCKDOWN_DEV_MODE', false ); // false = check for updates, true = never check
```

### Private repos

Public repos need nothing extra. For a private repo, create a fine-grained GitHub token limited to that one repo with **Contents: Read-only** access, and add it to each site's `wp-config.php`:

```php
define( 'ADMIN_IP_LOCKDOWN_GITHUB_TOKEN', 'github_pat_...' );
```

Never put a token in the plugin's own code: every site that installs the plugin would get a copy. For plugins sold or shipped to customers, use a public repo, or serve updates from your own server the way HighGround does.

Unauthenticated GitHub API requests are limited to 60 an hour per server IP. Each check makes a few requests every 12 hours, so this only matters when many sites share one IP. A token raises the limit.

## Structure

```
admin-ip-lockdown.php                         Plugin header, constants, boot, activation
uninstall.php                                 Deletes the options, table and user meta when the plugin is deleted
readme.txt                                    WordPress readme; feeds the "View details" popup
includes/
  class-admin-ip-lockdown-plugin.php          Main singleton, settings, activation and cron
  class-admin-ip-lockdown-guard.php           Enforcement: wp-login.php, wp-admin, XML-RPC, sign-ins, sessions
  class-admin-ip-lockdown-access.php          Allowed list, wp-config entries and temporary access
  class-admin-ip-lockdown-request.php         Visitor IP (Cloudflare, proxies) and signed loopbacks
  class-admin-ip-lockdown-ip.php              Address, range and hostname parsing and matching
  class-admin-ip-lockdown-cloudflare.php      Cloudflare's ranges and the weekly refresh
  class-admin-ip-lockdown-dns.php             Dynamic DNS hostname cache
  class-admin-ip-lockdown-unlock.php          Emergency unlock links
  class-admin-ip-lockdown-blocked.php         The "Access restricted" and unlock pages
  class-admin-ip-lockdown-log.php             Blocked attempts and unlock events
  class-admin-ip-lockdown-cli.php             WP-CLI commands
  class-admin-ip-lockdown-admin.php           Content Powered > Admin IP Lockdown page and Plugins-screen link
  class-admin-ip-lockdown-menu.php            Shared top-level "Content Powered" menu
  class-admin-ip-lockdown-feedback.php        Shared Submit Feedback and Report a Bug pages
  class-admin-ip-lockdown-updater.php         GitHub update checks (PUC wiring)
  class-admin-ip-lockdown-icons.php           Inline Lucide icon helper
assets/
  admin.css, admin.js                         Loaded only on the settings page
  icon.svg                                    Icon on the update screens
  content-powered.svg                         Sumo logo for the Content Powered menu
icons/                                        The Lucide icons the plugin uses (plus LICENSE)
plugin-update-checker/                        Plugin Update Checker 5.7 library
```

## The Content Powered menu

Every plugin made from this skeleton puts its settings page under one shared top-level **Content Powered** menu, so several installed plugins line up as Content Powered > Link Fixer, Content Powered > Fast Social Share Buttons, and so on.

Each plugin carries the same `class-admin-ip-lockdown-menu.php`. Whichever plugin loads first registers the menu (slug `content-powered`, sumo logo from `assets/content-powered.svg`); the others find it already there and only add their own page. The top-level link opens the first plugin's page. Keep the slug as it is, or plugins made from older copies would end up in a second menu.

The logo needs a single fill colour, because WordPress repaints menu icons to match each user's admin colour scheme.

## Feedback and bug reports

Every plugin also carries `class-admin-ip-lockdown-feedback.php`, which adds **Submit Feedback** and **Report a Bug** to the bottom of the Content Powered menu. The links appear once however many Content Powered plugins are active: each plugin adds itself to a shared list, and only the newest copy of the class (by its `VERSION` constant, the first loaded on a tie) adds the pages. With more than one plugin active, the form asks which plugin the message is about.

Messages go from the site's server to `https://www.contentpowered.com/wp-json/contentpowered/v1/plugin-feedback/` and show up on contentpowered.com under Our Plugins > Bug Reports and Our Plugins > Feedback. Each message carries a single-use secret, and contentpowered.com fetches its hash back from the site's `admin-ajax.php` to confirm the site really sent it. A site can send one message every 24 hours, and the page shows how long until the next one. The sidebar lists exactly what gets sent.

When you change the file, bump `VERSION` and copy it into the other plugins (with the names swapped), so the newest copy is the one that runs. To send messages to a local copy of contentpowered.com instead, add this to `wp-config.php`:

```php
define( 'CONTENT_POWERED_FEEDBACK_ENDPOINT', 'http://contentpowered/wp-json/contentpowered/v1/plugin-feedback/' );
```

## Update screen icon

To use your own icon on the update screens, replace `assets/icon.svg`. PNGs work too: delete the SVG and add `assets/icon-128x128.png` and `assets/icon-256x256.png`.

## Icons

The plugin bundles the [Lucide](https://lucide.dev/icons) icons it uses in `icons/`. Print one inline with:

```php
echo Admin_IP_Lockdown_Icons::get( 'package', 20 );           // name, size in px
echo Admin_IP_Lockdown_Icons::get( 'shield-check', 16, 'my-class' );
```

Icons use `currentColor`, so they take on the text colour around them. The name is the file name in `icons/` without `.svg`.

## Credits and licenses

This plugin uses these third-party assets under their own licenses:

- **[Lucide](https://lucide.dev) icons** (`icons/`): ISC License, Copyright (c) 2026 Lucide Icons and Contributors. Icons derived from [Feather](https://feathericons.com) are under the MIT License, Copyright (c) 2013-present Cole Bemis. Both licenses require their copyright and permission notice to ship with every copy, so keep `icons/LICENSE` alongside the icons.
- **[Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker)** (`plugin-update-checker/`): MIT License, Copyright (c) Janis Elsts. See `plugin-update-checker/license.txt`.

The plugin itself is licensed under GPL-2.0-or-later. See `LICENSE`.
