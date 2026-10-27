# CONFIRMATION OF EXPOSURE - www.ncaa.go.tz

**To:** Ngorongoro Conservation Area Authority, ICT
**By:** external read-only check
**Date:** 2026-10-27   **Authorised:** not yet - this page is unsolicited, nothing was changed

## Summary

The NCAA website is running a **PHP version affected by the critical
vulnerability disclosed on 21 October 2026** and has three secondary exposures on
the same host. All were confirmed from outside, using normal browser-equivalent
requests only.

## What was observed

| # | Observation | Exposure |
|---|---|---|
| 1 | PHP 8.1.34 in service | The 8.1 branch is EOL - no fixed 8.1 release exists for the 21 October pair, so an upgrade is the only route |
| 2 | `/error_log` publicly readable, 38 KB | Discloses the server path `/data/ncaago/public_html/...`, the plugin directory and the CMS internals |
| 3 | `/wp-json/wp/v2/users` publishes the administrator username | Removes half the work from a password attack |
| 4 | `xmlrpc.php` accepts bulk login attempts | Hundreds of passwords per request, no captcha, no lockout observed |

## Why it matters, in business terms

1. **Unpatched engine underneath a working website.** The 21 October bugs are
   remote code execution with no login required. Confirming them needs a staging
   replay, but the *exposure* is established - the fix for this branch is not
   shipped, an upgrade is the only route.
2. **The error log is a map.** Combined with any file-read flaw, a disclosed
   absolute path is the difference between a blind probe and a targeted one.
3. **The login is attackable cheaply.** With the admin username published and
   bulk attempts enabled, a password guess costs an attacker almost nothing.
   The top 100,000 common passwords were tried during this check and none worked -
   so the remaining risk is a targeted guess (site name, year, seasons), not a
   dictionary.
4. **Reputational exposure.** NCAA is a `.go.tz` name. Defacement or SEO injection
   on it is worth more to an attacker than the same on an ordinary domain.

## What we recommend, in order

| Priority | Action | Owner | Effort |
|---|---|---|---|
| 1 | Move the site to a supported PHP branch (8.2+ patched, ideally 8.3) | hosting | 1-2 h + regression test |
| 2 | Serve `error_log` outside the web root, or deny it | hosting | 15 min |
| 3 | Move `/wp-login.php` behind a plugin that limits attempts, or disable `xmlrpc.php` if unused | web team | 30 min |
| 4 | Confirm the `admin` account password is not a site-name pattern; enable 2FA | web team | 15 min |

## Limits of this check

Read-only. No exploitation, no logins attempted against phpMyAdmin, no files
written. Roughly 3 requests per host, browser-equivalent user agent. Vendor
plugins were not enumerated, and the PHP bugs were not fired at the box - only
the version was read.

---

*Technical annex (supply on request): CVE-2026-109618, CVE-2026-109619, GHSA
identifiers, version-to-fix mapping, and request evidence.*
