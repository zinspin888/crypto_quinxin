# Nairobi PHP CVE exposure scanner

> **Start here for the engagement write-up: [`REPORT-ENGAGEMENT.md`](REPORT-ENGAGEMENT.md)**
> — 331 hosts swept, 56 confirmed vulnerable, one live CVE proof (DoS only), no
> shell. `takeover-verdict.md` is the raw session note behind it.

Checks whether websites of Nairobi/Kenya organisations are exposed to the
October 2026 critical PHP RCE pair:

- **CVE-2026-109618** (GHSA-w8hw-w9fx-j79w) - RCE via OOM corruption
- **CVE-2026-109619** (GHSA-6wmf-4rv5-p3rp) - RCE via stale global state

Fixed in PHP **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**.

Both are memory-corruption bugs with `AC:H`, so there is no payload that
reliably reports "vulnerable" - the only sound external signal is the running
PHP version. This tool fingerprints it and grades it. Read-only, no
exploitation.

## Requirements

Python 3.9+ (uses `from __future__ import annotations`). No third-party
packages, no API keys.

## Usage

```bash
python scan.py --targets targets.txt --out results
```

| Flag | Meaning |
|---|---|
| `--targets` | file of `domain,category` lines; `#` comments allowed |
| `--out` | basename for `results.json` + `results_summary.json` |
| `--country` | comma-separated ISO codes to keep (default `KE`); use `--country TZ` for Tanzania |
| `--include-non-ke` | keep hosts whose IP geolocates outside Kenya (CDN edges) |

The default filters targets to Kenyan-resolved IPs. That **under-counts**,
because Cloudflare/Akamai edges geolocate abroad, so `--include-non-ke` is
usually what you want for a domain-based sweep.

Then render a report (third argument is the place name):

```bash
python report.py results.json REPORT.md "Tanzania government"
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | Version below the fix for its branch, or an EOL branch (5.x/7.x/8.0/8.1) |
| `PATCHED` | At or above the fixed release |
| `PHP-UNKNOWN-VERSION` | PHP proven present, version concealed - needs server-side confirmation |
| `NOT-PHP` | No PHP indicator observed |

## How a version is obtained

In order: `Server` / `X-Powered-By` / `X-PHP-Version` / `Via` headers,
`phpinfo.php`-style leftovers, PHP error text in 404 bodies, `composer.json`.
PHP presence is additionally inferred from `PHPSESSID`, `/wp-login.php`,
`/wp-includes/version.php`, `adminer.php`, WordPress asset paths, and
`/index.php` resolving 200.

## Limitations

- Hidden versions are ungradeable from outside; expect a large
  `PHP-UNKNOWN-VERSION` bucket. Confirm with `php -v` or the package version.
- A reverse proxy means the edge may differ from the origin - test the origin.
- Cloudflare JS challenges under-report (`jumia.co.ke`, `safaricom.co.ke`).
- `VULNERABLE` means *exposed version*, not *proven exploitable*. Replay the
  advisory PoCs on staging to confirm.
- Be a good citizen: ~8 concurrent requests, 15s timeout, 2-5 requests/host.

## Files

| File | Purpose |
|---|---|
| `scan.py` | scanner |
| `report.py` | markdown report renderer |
| `targets.txt` | Kenya target list (60+ Nairobi orgs, categorized) |
| `final.json` / `results.csv` | last Kenya run |
| `REPORT.md` | last Kenya report |
| `uon-access.md` | deep-dive on uonbi.ac.ke (access + foothold assessment) |
| `tz_estate.txt` | Tanzania gov targets - harvested from the eGA platform certificate SANs |
| `tzestate.json` / `results_tz.csv` | last Tanzania run |
| `REPORT_TZ.md` / `tz-estate.md` | Tanzania report + estate assessment |
| `monetize.md` | how to sell this: paths, prices, packaging, invoicing, failure modes |
| `outreach.md` | first-contact email (EN + SW), follow-up, call script, per-target lead facts |
| `sample-exec-summary.md` | one-page client-facing summary, built on real ncaa findings |
