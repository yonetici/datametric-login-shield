# Datametric Login Shield

Hide your WordPress login URL and lock down access — a modular login-security plugin by **Datametric**.

> A rebranded, hardened fork of [WPS Hide Login](https://wordpress.org/plugins/wps-hide-login/) (GPLv2 or later). See **Credits** in [`readme.txt`](readme.txt).

## Features (free)

- **Hide login URL** — change `wp-login.php` to a custom, hard-to-guess address; block `wp-login.php` / `wp-admin` for logged-out visitors.
- **Brute-force protection** — lock out an IP after too many failed logins (configurable), with an allowlist and fail-open safety.
- **Access hardening** — block REST user enumeration (`/wp/v2/users`), block `?author=N` scans, generic login errors, optional XML-RPC disable.
- **Login audit log** — successful/failed logins, lockouts and logouts with date, user and IP; 7-day history; optional IP anonymization.
- **Modern admin panel** with copy / email-your-URL anti-lockout tools.
- One-click import of an existing WPS Hide Login URL. Multisite compatible. No external calls.

## Architecture

A small service container + module registry. Each feature is a `ModuleInterface` registered via the `dmls_register_modules` filter; a future **Pro** add-on plugs into the same filter and the `dmls_settings_tabs` registry without the free plugin referencing it.

```
datametric-login-shield.php   # bootstrap
src/
  Plugin.php  Container.php  Autoloader.php
  Contracts/ModuleInterface.php
  Support/    Options.php  Database.php  Ip.php  Singleton.php
  Admin/      SettingsPage.php  Settings.php
  Modules/    HideLogin/  BruteForce/  Hardening/  AuditLog/
assets/  languages/  readme.txt  uninstall.php
```

## Development

Requires PHP 7.2+ (CI runs 7.4).

```bash
composer install          # dev tools (PHPCS + WPCS + PHPCompatibility)
composer lint             # check WordPress coding standards
composer lint:fix         # auto-fix where possible
./build.sh                # produce dist/datametric-login-shield.<version>.zip
```

`.distignore` controls what is excluded from the shipped zip / WordPress.org SVN.

## Continuous integration

- **CI** (`.github/workflows/ci.yml`) — runs PHP lint, PHPCS (WordPress standards) and the official **WordPress Plugin Check** on every push / PR.
- **Deploy** (`.github/workflows/deploy.yml`) — on pushing a version tag (e.g. `1.1.0`), deploys to the WordPress.org plugin directory via the [10up deploy action](https://github.com/10up/action-wordpress-plugin-deploy).

### Releasing to WordPress.org (after the plugin is approved)

1. Add two repository secrets (Settings → Secrets and variables → Actions):
   - `SVN_USERNAME` — your WordPress.org username.
   - `SVN_PASSWORD` — your WordPress.org password.
2. Bump the version in `datametric-login-shield.php` (`Version:` header **and** `DMLS_VERSION`) and in `readme.txt` (`Stable tag`), and add a changelog entry.
3. Commit, then tag and push:
   ```bash
   git tag 1.1.0
   git push origin 1.1.0
   ```
   The deploy workflow tags the release in SVN and uploads a built zip artifact.

> The very first version must be submitted manually once via https://wordpress.org/plugins/developers/add/ and approved by the Plugin Review team before automated deploys can push updates.

## License

GPLv2 or later. See [`LICENSE`](LICENSE).
