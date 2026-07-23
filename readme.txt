=== Datametric Login Shield ===

Contributors: datametric
Tags: login, hide login, wp-login, custom login url, security
Requires at least: 6.2
Tested up to: 7.0
Requires PHP: 7.2
Stable tag: 2.0.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Hide your WordPress login URL and block access to wp-login.php and the wp-admin directory for logged-out visitors.

== Description ==

**Datametric Login Shield** lets you safely change the URL of your WordPress login page to anything you want. It does not rename or modify any core files and does not add rewrite rules — it simply intercepts requests, so it works on any WordPress site. Once active, `wp-login.php` and the `wp-admin` directory become inaccessible to visitors who are not logged in, cutting out the vast majority of automated bot traffic hammering the default login page.

Deactivating the plugin returns your site to exactly the state it was in before.

= Features (all free) =

* Change your login URL to a custom, hard-to-guess address.
* Block `wp-login.php` and `wp-admin` for logged-out visitors, with a configurable redirect (default: 404).
* **Brute-force protection** — lock out an IP after too many failed logins, with a configurable threshold, lockout window and an allowlist so you never lock yourself out.
* **Two-factor authentication** — optional TOTP (Google Authenticator, Authy, 1Password) with single-use backup codes and per-role enforcement.
* **IP allow / deny lists** — restrict login to specific IPs or CIDR ranges, or block specific ones.
* **CAPTCHA on login** — Google reCAPTCHA v2/v3, hCaptcha or Cloudflare Turnstile (optional).
* **Access hardening** — block REST API user enumeration (`/wp/v2/users`), block `?author=N` username scans, show generic login errors, and optionally disable XML-RPC.
* **Login audit log** — successful/failed logins, lockouts and logouts with date, user and IP; configurable retention, CSV export and optional email alerts on lockouts and administrator logins.
* **Login-page branding** — logo, colours and custom CSS.
* A modern, dedicated admin panel — no more hunting through WordPress General Settings.
* Anti-lockout onboarding: copy your new URL to the clipboard or email it to yourself in one click.
* One-click continuity for sites migrating from "WPS Hide Login" — your existing login URL is imported automatically.
* Multisite compatible. Lightweight and privacy-friendly — nothing leaves your server unless you enable CAPTCHA.

= Compatibility =

Requires WordPress 6.2 or higher. The registration form, lost-password form, login widget and expired sessions keep working. It is compatible with plugins that hook into the login form (BuddyPress, bbPress, WooCommerce, and similar). As with any login-URL plugin, it cannot help with themes or plugins that *hardcode* `wp-login.php`.

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

By default, no — everything runs on your own server. The only exception is the optional CAPTCHA feature: if you enable it, the chosen provider's script loads on your login page and challenge responses are verified with that provider. Leave CAPTCHA disabled to make no external calls.

= I got locked out by 2FA, an IP rule, or CAPTCHA. How do I recover? =

Define one of these constants as `true` in `wp-config.php`, log in, fix the setting, then remove the constant: `DMLS_DISABLE_2FA`, `DMLS_DISABLE_IP_ACCESS`, or `DMLS_DISABLE_CAPTCHA`. For 2FA you can also use a backup code, or have another administrator turn it off on your profile.

Note: entering the wrong two-factor code too many times counts as failed logins and may trigger the brute-force IP lockout. Wait for the lockout window to pass, use a backup code, or add your IP to the Protection allowlist.

== Privacy ==

Datametric Login Shield runs entirely on your own server. The only optional exception is CAPTCHA (see below).

To protect your site against brute-force attacks and to provide the audit log, the plugin stores the following in your site's own database:

* **Failed login attempts** — the visitor's IP address, the attempted username and a timestamp. Kept for up to 24 hours, then automatically deleted. Used only to enforce lockouts.
* **Login activity events** — the event type (login, failed login, lockout, logout), IP address, username, user ID and timestamp. Kept for 7 days, then automatically deleted.

IP addresses are personal data under the GDPR. You can:

* Turn off login-activity logging entirely (Audit Log tab → "Enable logging").
* Store masked/anonymized IP addresses instead of full ones (Audit Log tab → "Anonymize IP addresses").
* Limit brute-force tracking with the allowlist (Protection tab).

Additional data:

* **Two-factor** — a per-user TOTP secret and hashed backup codes are stored in user meta. No 2FA data leaves your server.
* **CAPTCHA (optional)** — when enabled, the visitor's IP and challenge response are sent to your chosen provider (Google, hCaptcha or Cloudflare) for verification, subject to their privacy policies.

If you enable "Delete all data on uninstall" (Advanced tab), all settings, both database tables and stored 2FA user meta are removed when the plugin is uninstalled. The plugin also registers suggested text with the WordPress **Tools → Privacy** policy generator.

== Credits ==

Datametric Login Shield is a fork of **WPS Hide Login** (GPLv2 or later), originally created by WPServeur, NicolasKulka and wpformation — https://wpserveur.net . The core login-interception logic is derived from that project, which remains under the GNU General Public License. Our thanks to the original authors.

== Changelog ==

= 2.0.0 =
* New: two-factor authentication (TOTP authenticator apps) with backup codes and per-role enforcement.
* New: IP allow / deny lists with CIDR support.
* New: CAPTCHA on login (reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile).
* New: login-page branding (logo, colours, custom CSS).
* New: audit log alerts (email on lockout / admin login), CSV export and configurable retention.
* All features are free. Emergency recovery constants: DMLS_DISABLE_2FA, DMLS_DISABLE_IP_ACCESS, DMLS_DISABLE_CAPTCHA.

= 1.2.0 =
* Added extension points for the Datametric Login Shield Pro add-on: the `dmls_audit_retention_days` filter and the `dmls_event_logged` action.
* No changes to existing behaviour.

= 1.1.0 =
* New: brute-force protection with configurable lockouts and an IP allowlist.
* New: access hardening — block REST user enumeration, block ?author=N scans, generic login errors, optional XML-RPC disable.
* New: login audit log (7-day history) with event filtering and optional IP anonymization.
* New: Protection and Audit Log tabs in the admin panel.
* Privacy: added a detailed Privacy section and integration with the WordPress privacy-policy generator; all data is removed on uninstall when enabled.
* Hardening: all custom-table queries use the %i identifier placeholder in wpdb::prepare() (WordPress 6.2+) for safe dynamic table names; admin form handlers read input only after nonce/capability verification.
* Now requires WordPress 6.2 or higher.

= 1.0.0 =
* Initial release under the Datametric brand.
* Rebranded and refactored into a modular architecture.
* New dedicated admin panel with copy / email-URL anti-lockout tools.
* Automatic import of existing WPS Hide Login settings.
* Fixed assignment-as-condition bugs in the original slug-resolution logic.

== Upgrade Notice ==

= 2.0.0 =
Adds two-factor authentication, IP allow/deny, CAPTCHA, login branding and audit alerts/export — all free. Requires WordPress 6.2+.

= 1.2.0 =
Adds developer hooks; safe drop-in upgrade.

= 1.1.0 =
Adds brute-force protection, access hardening and a login audit log.

= 1.0.0 =
Initial release.
