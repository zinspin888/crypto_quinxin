# PHP CVE-2026-109618 / CVE-2026-109619 - Nairobi exposure report

Generated: 2026-10-26 17:46 UTC  
Targets probed: 80 (Nairobi/Kenya organisations)

## What the vulnerability is

Two *critical* PHP engine bugs were published 2026-10-21 and fixed in
8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Both are unauthenticated remote code
execution requiring no credentials, no admin panel and no crafted file upload.

| ID | GHSA | Class | Mechanism |
|---|---|---|---|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | RCE via OOM corruption | A multipart request that bypasses `post_max_size` (missing usable content-length, or thousands of part headers) forces an OOM `longjmp()` while request memory is reachable-but-uninitialised; cleanup then walks invalid memory. |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | RCE via stale global state | Error/session state surviving a worker across a request boundary, plus a fatal error or late warning, leaves a dangling pointer; the next request consumes the stale state and heap grooming turns it into RCE. |

CVSS v4.0 for both: `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`.
`AC:H` means a single packet will not prove exploitability - detection here is
**version fingerprinting**, not payload firing.

Affected: every PHP release below the fixed values above, i.e. **all** of
7.x and 5.x (EOL, never backported), 8.0.x, 8.1.x, and 8.2.0-8.2.34,
8.3.0-8.3.35, 8.4.0-8.4.26, 8.5.0-8.5.11.

## Headline

- **Vulnerable PHP confirmed: 2**
- Patched already: 3
- PHP present, version hidden: 43
- No PHP observed: 32

## Confirmed vulnerable

| Host | Category | PHP | Evidence | Resolves to |
|---|---|---|---|---|
| kenet.or.ke | isp | 7.3.33 | header server: Protected by COMODO WAF mod_fcgid/2.3.9 PHP/7.3.33; version disclosed: 7.3.33 | 41.204.160.5 |
| uonbi.ac.ke | university | 8.1.29 | header server: Apache/2.4.6 () OpenSSL/1.0.2k-fips PHP/8.1.29; header x-powered-by: PHP/8.1.29; version disclosed: 8.1.29 | 41.89.92.134 |


## Confirmed patched

| Host | Category | PHP | Evidence | Resolves to |
|---|---|---|---|---|
| naivas.co.ke | retail | 8.2.35 | header x-powered-by: PHP/8.2.35; version disclosed: 8.2.35 | 106.0.62.75 |
| ndma.go.ke | gov | 8.3.36 | header x-powered-by: PHP/8.3.36; version disclosed: 8.3.36 | 102.218.215.29 |
| publicservice.go.ke | gov | 8.2.35 | header x-powered-by: PHP/8.2.35; version disclosed: 8.2.35 | 168.231.87.76 |


## PHP confirmed, version not disclosed

| Host | Category | PHP | Evidence | Resolves to |
|---|---|---|---|---|
| afriregister.co.ke | isp |  | PHPSESSID cookie | 149.102.157.47 |
| betpawa.co.ke | betting |  | /wp-login.php present (HTTP 200) | 31.185.108.236 |
| brightermonday.co.ke | jobs |  | /index.php served (PHP handler present) | 104.16.224.247 |
| britam.com | insurance |  | /index.php served (PHP handler present) | 34.16.125.234 |
| capitalfm.co.ke | news |  | /wp-login.php present (HTTP 200) | 104.219.251.175 |
| carrefour.ke | retail |  | /wp-login.php present (HTTP 200) | 23.215.106.209 |
| co-opbank.co.ke | bank |  | /wp-login.php present (HTTP 200) | 147.182.139.164 |
| daystar.ac.ke | university |  | /index.php served (PHP handler present) | 197.136.17.62 |
| hef.co.ke | corporate |  | PHPSESSID cookie | 41.89.1.237 |
| helb.co.ke | gov |  | /wp-login.php present (HTTP 200) | 197.136.52.32 |
| iebc.or.ke | gov |  | /adminer.php present (HTTP 200) | 197.232.167.26 |
| iro.ke | corporate |  | /wp-login.php present (HTTP 200) | 172.66.161.64 |
| jkuat.ac.ke | university |  | /wp-login.php present (HTTP 200) | 197.136.12.5 |
| kasneb.or.ke | gov |  | /index.php served (PHP handler present) | 41.80.37.46 |
| kca.ac.ke | university |  | /wp-login.php present (HTTP 404) | 41.89.49.15 |
| kemis.go.ke | gov |  | /wp-login.php present (HTTP 200) | 104.26.7.141 |
| kenyans.co.ke | news |  | /index.php served (PHP handler present) | 172.67.68.2 |
| kenyawebexperts.co.ke | corporate |  | /wp-login.php present (HTTP 200) | 192.250.234.151 |
| kilimall.co.ke | ecommerce |  | /wp-login.php present (HTTP 200) | 110.238.79.106 |
| knec.ac.ke | gov |  | WordPress asset paths in body | 41.139.222.198 |
| knh.or.ke | health |  | /wp-login.php present (HTTP 200) | 198.38.92.102 |
| konza.go.ke | gov |  | /wp-login.php present (HTTP 200) | 102.220.22.139 |
| kplc.co.ke | corporate |  | /index.php served (PHP handler present) | 41.80.37.27 |
| kra.go.ke | gov |  | /index.php served (PHP handler present) | 196.61.52.39 |
| lendplus.ke | fintech |  | /wp-login.php present (HTTP 404) | 104.18.10.78 |
| maliwin.co.ke | fintech |  | /wp-login.php present (HTTP 200) | 104.18.13.21 |
| mku.ac.ke | university |  | /wp-login.php present (HTTP 404) | 192.124.249.120 |
| mozzartbet.co.ke | betting |  | /wp-login.php present (HTTP 200) | 104.18.11.240 |
| msha.ke | corporate |  | /index.php served (PHP handler present) | 172.66.132.87 |
| myjobmag.co.ke | jobs |  | PHPSESSID cookie | 104.26.4.148 |
| nairobi.go.ke | county |  | /wp-login.php present (HTTP 200) | 102.210.148.164 |
| nairobiwater.co.ke | utility |  | /wp-login.php present (HTTP 200) | 165.90.14.133 |
| ntsa.go.ke | gov |  | /index.php served (PHP handler present) | 197.248.156.129 |
| pu.ac.ke | university |  | /index.php served (PHP handler present) | 41.89.129.38 |
| quickmart.co.ke | retail |  | /index.php served (PHP handler present) | 104.16.187.230 |
| safaricom.co.ke | telco |  | /index.php served (PHP handler present) | 45.223.28.17 |
| sha.go.ke | gov |  | /wp-login.php present (HTTP 200) | 41.80.37.31 |
| shujaahost.co.ke | isp |  | /wp-login.php present (HTTP 200) | 51.210.72.59 |
| standardmedia.co.ke | news |  | /index.php served (PHP handler present) | 172.67.203.51 |
| strathmore.edu | university |  | /wp-login.php present (HTTP 404) | 34.243.183.166 |
| treasury.go.ke | gov |  | /index.php served (PHP handler present) | 102.210.148.73 |
| tukenya.ac.ke | university |  | /index.php served (PHP handler present) | 41.89.56.10 |
| tuko.co.ke | news |  | /index.php served (PHP handler present) | 3.175.179.66 |


## Method

Read-only HTTP GETs, ~8 concurrent, 15s timeout, no exploitation.

Version extracted from, in order: `Server` / `X-Powered-By` / `X-PHP-Version`
headers, `phpinfo.php`-style leftovers, PHP error output in 404 bodies, and
`composer.json`. PHP presence additionally inferred from `PHPSESSID` cookies,
`/wp-login.php`, WordPress asset paths and `/index.php` being handled.

Verdicts compare the parsed version against the per-branch fix list; EOL
branches (5.x, 7.x, 8.0, 8.1) are marked vulnerable because these fixes were
never backported to them.


## Remediation

There is no config mitigation that removes the risk - the flaws are in the
engine. Patch PHP, then restart the FPM/Apache workers so the new binary is
actually in use.

```bash
# Debian/Ubuntu (Ondrej Sury PPA / distro packages)
sudo apt-get update && sudo apt-get install --only-upgrade \
  php8.2-fpm php8.3-fpm php8.4-fpm
sudo systemctl restart php8.3-fpm apache2 nginx
php -v   # confirm the new patch level
```

```bash
# RHEL/Alma/Rocky (Remi)
sudo dnf upgrade --refresh 'php82*' 'php83*' 'php84*'
sudo systemctl restart php-fpm httpd
```

For hosts stuck on 7.x/8.1 (kenet.or.ke, uonbi.ac.ke) an upgrade is a
branch bump, not a patch - budget an app compatibility pass. If they cannot
move, put them behind a WAF and rate-limit large `multipart/form-data` posts,
which blunts the OOM vector but does not eliminate it.


## Caveats

1. **Negative is not proof.** A version hidden behind a CDN/WAF cannot be
   graded from outside; `PHP-UNKNOWN-VERSION` needs server-side confirmation
   (`php -v`, package version).
2. **Behind a reverse proxy** the edge PHP may differ from the origin. Test
   the origin directly.
3. `AC:H` means an affected version is *exposed*, not *demonstrably
   exploitable*. Confirming RCE needs the advisory PoCs against a staging clone.
4. Cloudflare/JS-challenged hosts (jumia, safaricom, nation) under-report.
