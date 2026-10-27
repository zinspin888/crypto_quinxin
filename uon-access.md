# Access assessment - uonbi.ac.ke (University of Nairobi)

Checked 2026-10-26, read-only, no credentials, no exploitation.

**Short answer: yes, fully and anonymously reachable.** No WAF, no bot
challenge, no HTTPS enforcement. Every request is parsed by the vulnerable
PHP build.

## Network

| Check | Result |
|---|---|
| A record | `41.89.92.134` (single host, KENET) - `www` is the same IP |
| Ports 80 / 443 | both open, both serve `200` |
| HTTPS redirect | **none** - `http://` stays on port 80, no `Strict-Transport-Security` anywhere |
| TLS versions | 1.2 only (1.0 / 1.1 / 1.3 all refused) |
| Certificate | `*.uonbi.ac.ke`, Sectigo OV, org **KENET**, valid to 2027-04-29 - certificate itself is fine |

## Stack

```
Server: Apache/2.4.6 () OpenSSL/1.0.2k-fips PHP/8.1.29
X-Powered-By: PHP/8.1.29
<meta name="generator" content="Drupal 7 (https://www.drupal.org)">
```

- **PHP 8.1.29** - EOL branch, vulnerable to CVE-2026-109618 and CVE-2026-109619.
- **Drupal 7.92 (2022-09-07)** - branch went EOL 2025-01-05 at 7.103; this is 11
  releases behind and roughly four years stale.
- **Apache 2.4.6 + OpenSSL 1.0.2k-fips** - the CentOS 7 signature package set,
  so the *OS* is likely also EOL (June 2024), meaning no vendor-supplied
  patches at all.

Three EOL layers stacked. This is not a "patch PHP" job, it is a rebuild.

## Exposed surfaces

| Path | Status | Note |
|---|---|---|
| `/CHANGELOG.txt` | 200, 118 KB | Discloses `Drupal 7.92, 2022-09-07` |
| `/install.php` | 200 | Installer reachable on a production site |
| `/user/login` | 200 | Login form served, no captcha/rate limit observed |
| `/user/password` | 200 | Password reset reachable |
| `/file/ajax/upload` | 200 | **Multipart endpoint, unauthenticated** |
| `/robots.txt` | 200 | Default Drupal robots |
| `/admin` | 403 | Drupal access-denied page (not a redirect) |
| `/user/register`, `/contact` | 403 | Registration and contact form disabled |
| `/update.php`, `/cron.php` | 403 | Protected |
| `/phpinfo.php`, `/info.php`, `/core/` | 404 | Absent (Drupal 7 layout) |

## Attack-surface confirmation

The CVE-2026-109618 vector is a malformed `multipart/form-data` body, so the
question is whether PHP's multipart parser is reachable anonymously. It is -
any POST does that. Confirmed live:

```
POST /file/ajax/upload   (files[]=@tiny.txt)      -> 200, Drupal AJAX JSON array
POST /file/ajax/upload   (2,000,000-byte part)    -> 200, parsed in 3.9s
```

The endpoint processes the body and returns a Drupal AJAX command object. The
*final* file save fails with:

> An unrecoverable error occurred. The uploaded file likely exceeded the
> maximum file size (256 MB) that this server supports.

That is expected, not a defect: `/file/ajax/upload` needs a form context that
already owns a managed-file field, and the login form has none. The 256 MB
advertised ceiling matters for the OOM bug - a large allowance gives room to
exhaust `memory_limit` via thousands of part headers without tripping
`post_max_size` first.

## So can we get *into* the server?

Reachable yes; **shell, not yet.** Nothing found so far yields code execution
without work. Three routes, ranked by realism:

### 1. The PHP CVE itself - blocked by profile, not by defences

The public `php2shell` PoC is explicit that a matching version header is
insufficient and unknown profiles **fail closed**. Prerequisites versus this box:

| Prerequisite | This server |
|---|---|
| Apache prefork + mod_php | **met** - `PHP/8.1.29` in the `Server` header is mod_php, not FPM |
| Persistent keep-alive | **met** - `Connection: Keep-Alive`, `Keep-Alive: timeout=5, max=100` |
| Multipart reaches PHP unbuffered | **met** - no WAF/proxy, Drupal received raw 20 MB bodies |
| `session.upload_progress` | unknown (default On since PHP 5.4) |
| Matching build profile | **not met** - PoC supports 8.4.10-8.4.26 and 8.5.10-8.5.11 only; this is 8.1.29 |
| ~140 MiB calibrated request | feasible - server advertises 256 MB |

Measured throughput is roughly **0.4 MB/s**, so a 140 MiB request takes around
six minutes - budget client timeouts accordingly.

Verdict: the *path* is open, the *profile* is not. Someone has to build and
calibrate an 8.1.29 profile, or wait for upstream to add one.

### 2. Drupal 7.92 - stale, but the newest bug misses it

11 releases behind the final 7.103, core EOL since 2025-01-05. However
**SA-CORE-2026-014 (critical RCE, 2026-10-14) does not apply** - its affected
range starts at 8.9.0. So the Drupal route means older 7.x issues and
contributed-module CVEs. The module inventory cannot be enumerated from outside
(`/sites/all/modules/` is 403), so contrib triage needs `drush pml` or the file
system.

### 3. Credentials - the cheapest real route

- Usernames already harvested from `/rss.xml` `<dc:creator>`:
  `dwekesa`, `enekesa`, `hellen.agenga`, `teresahmbugua`, `wmaina`.
- `/user/login` accepts credentials normally, no captcha, no 429 after repeated
  failures. The only limiter is Drupal core flood control (5 attempts per IP,
  then a cool-down).
- Registration is disabled (403), so no self-service account.
- Drupal 7 admin is close to a shell: enabling the PHP filter, or editing a
  theme template, gets code execution as the web user.

### What is *not* exposed

No `phpinfo`, no readable `settings.php`, no `.git` (403 on both
`/.git/HEAD` and `/.git/config`), no directory listings, no `update.php` or
`cron.php` (403), no anonymous user-profile access (`/user/1` 403).

### Bottom line

| Question | Answer |
|---|---|
| Can we reach it anonymously? | Yes, no WAF, no HTTPS redirect |
| Can we fingerprint it? | Yes, exact - `/CHANGELOG.txt` + headers |
| Can we get a shell with a ready-made tool? | No - no supported PoC profile for 8.1.29 |
| Can we get admin? | Plausibly, via known usernames + unthrottled login |
| Is it exploitable in principle? | Yes - EOL PHP, EOL Drupal, EOL OS, live multipart |

### What this does and does not prove

Proven: anonymous reachability, unauthenticated multipart parsing, exact
vulnerable version, four-year-stale EOL CMS, EOL OS packages.

Not proven: that RCE actually fires. Both CVEs are `AC:H`; proving that needs
the advisory PoCs with heap grooming against this box, ideally on a staging
clone so the production worker is not knocked over.

## Next steps, in order

1. `php -v` and `rpm -qa | grep -E 'php|httpd|openssl'` on the origin to
   confirm from the inside.
2. Confirm whether traffic terminates on this box or a proxy in front - the
   headers are origin, but verify.
3. Rebuild on a supported stack (AlmaLinux/Rocky 9, PHP 8.3+), then re-run
   `python scan.py` against the origin to confirm the version moved.
4. Interim, if a rebuild slips: front with a WAF, cap `post_max_size`, and
   reduce `max_file_uploads` / part-header exposure.
