=== Datametric Login Shield ===

Contributors: datametric
Tags: login, hide login, wp-login, custom login url, security
Requires at least: 5.3
Tested up to: 6.9
Requires PHP: 7.2
Stable tag: 1.1.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Hide your WordPress login URL and block access to wp-login.php and the wp-admin directory for logged-out visitors.

== Description ==

**Datametric Login Shield** lets you safely change the URL of your WordPress login page to anything you want. It does not rename or modify any core files and does not add rewrite rules — it simply intercepts requests, so it works on any WordPress site. Once active, `wp-login.php` and the `wp-admin` directory become inaccessible to visitors who are not logged in, cutting out the vast majority of automated bot traffic hammering the default login page.

Deactivating the plugin returns your site to exactly the state it was in before.

= Key features (free) =

* Change your login URL to a custom, hard-to-guess address.
* Block `wp-login.php` and `wp-admin` for logged-out visitors, with a configurable redirect (default: 404).
* **Brute-force protection** — lock out an IP after too many failed logins, with a configurable threshold, lockout window and an allowlist so you never lock yourself out.
* **Access hardening** — block REST API user enumeration (`/wp/v2/users`), block `?author=N` username scans, show generic login errors, and optionally disable XML-RPC.
* **Login audit log** — see successful logins, failed logins, lockouts and logouts with date, user and IP; 7 days of history, with optional IP anonymization.
* A modern, dedicated admin panel — no more hunting through WordPress General Settings.
* Anti-lockout onboarding: copy your new URL to the clipboard or email it to yourself in one click.
* One-click continuity for sites migrating from "WPS Hide Login" — your existing login URL is imported automatically.
* Multisite compatible.
* Lightweight, dependency-free, and privacy-friendly — nothing is sent to external servers.

= Coming soon (Datametric Login Shield Pro) =

Two-factor authentication with authenticator apps, IP allow/deny lists, CAPTCHA on login, unlimited audit-log history with alerts, and full custom login-page branding / white-label.

= Compatibility =

Requires WordPress 5.3 or higher. The registration form, lost-password form, login widget and expired sessions keep working. It is compatible with plugins that hook into the login form (BuddyPress, bbPress, WooCommerce, and similar). As with any login-URL plugin, it cannot help with themes or plugins that *hardcode* `wp-login.php`.

== Installation ==

1. Upload the `datametric-login-shield` folder to `/wp-content/plugins/`, or install the plugin through the **Plugins** screen in WordPress.
2. Activate the plugin through the **Plugins** screen.
3. Go to **Login Shield** in the admin menu, set your custom login URL, and **save the URL somewhere safe** (use the "Email this URL to me" button).

== Frequently Asked Questions ==

= I locked myself out. What do I do? =

Deactivate the plugin by renaming its folder in `/wp-content/plugins/` via FTP or your host's file manager. Your default login (`wp-login.php`) will work again immediately.

= Does it work with caching plugins? =

Yes, but make sure your custom login URL is not cached as a static page. Most caching plugins exclude login pages automatically.

= Is my data sent anywhere? =

No. The free version operates entirely on your own server and does not contact any external service.

== Privacy ==

Datametric Login Shield operates entirely on your own server and does **not** contact or send data to any external service.

To protect your site against brute-force attacks and to provide the audit log, the plugin stores the following in your site's own database:

* **Failed login attempts** — the visitor's IP address, the attempted username and a timestamp. Kept for up to 24 hours, then automatically deleted. Used only to enforce lockouts.
* **Login activity events** — the event type (login, failed login, lockout, logout), IP address, username, user ID and timestamp. Kept for 7 days, then automatically deleted.

IP addresses are personal data under the GDPR. You can:

* Turn off login-activity logging entirely (Audit Log tab → "Enable logging").
* Store masked/anonymized IP addresses instead of full ones (Audit Log tab → "Anonymize IP addresses").
* Limit brute-force tracking with the allowlist (Protection tab).

If you enable "Delete all data on uninstall" (Advanced tab), all settings and both database tables are removed when the plugin is uninstalled. The plugin also registers suggested text with the WordPress **Tools → Privacy** policy generator.

The free version contacts no third-party services and sets no cookies of its own.

== Credits ==

Datametric Login Shield is a fork of **WPS Hide Login** (GPLv2 or later), originally created by WPServeur, NicolasKulka and wpformation — https://wpserveur.net . The core login-interception logic is derived from that project, which remains under the GNU General Public License. Our thanks to the original authors.

== Changelog ==

= 1.1.0 =
* New: brute-force protection with configurable lockouts and an IP allowlist.
* New: access hardening — block REST user enumeration, block ?author=N scans, generic login errors, optional XML-RPC disable.
* New: login audit log (7-day history) with event filtering and optional IP anonymization.
* New: Protection and Audit Log tabs in the admin panel.
* Privacy: added a detailed Privacy section and integration with the WordPress privacy-policy generator; all data is removed on uninstall when enabled.

= 1.0.0 =
* Initial release under the Datametric brand.
* Rebranded and refactored into a modular architecture.
* New dedicated admin panel with copy / email-URL anti-lockout tools.
* Automatic import of existing WPS Hide Login settings.
* Fixed assignment-as-condition bugs in the original slug-resolution logic.

== Upgrade Notice ==

= 1.1.0 =
Adds brute-force protection, access hardening and a login audit log.

= 1.0.0 =
Initial release.
