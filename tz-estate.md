# Tanzania government estate - PHP exposure assessment

Scanned 2026-10-26. 251 hosts, all under the `.go.tz` / government-platform
certificate issued to the **e-Government Authority (eGA)**. Read-only, no
exploitation.

CVE-2026-109618 / CVE-2026-109619, fixed in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

## Headline

| Verdict | Count |
|---|---|
| **Vulnerable PHP confirmed** | **54** |
| Patched | 4 |
| PHP present, version hidden | 133 |
| No PHP observed | 60 |

**54 of 251 live government hosts are on PHP versions exposed to both
unauthenticated RCEs. Four have been patched.** Everything is on one
provider's infrastructure, so this is a single patching programme, not
54 separate problems.

## Version spread

Almost none of the estate is on a supported branch.

| PHP | Hosts | Severity context |
|---|---|---|
| 5.6.40 | 8 | EOL Dec 2018 - no security support for ~8 years |
| 7.0.33 | 3 | EOL Jan 2019 |
| 7.2.34 | 12 | EOL Nov 2020 |
| 7.3.33 | 12 | EOL Dec 2021 |
| 7.4.33 | 8 | EOL Nov 2022 |
| 8.0.30 | 8 | EOL Nov 2023 |
| 8.1.34 | 3 | EOL Dec 2025 |

Every one of these is below the fix and none of the branches still receive
security backports (php.net supports 8.2-8.5 only), so **an upgrade is the
only remedy** for all 54 - there is no patch to apply in place.

## Concentration

Three servers, all eGA-operated:

| Server | Vuln hosts | Versions present |
|---|---|---|
| `154.118.230.167` | 28 | 5.6.40, 7.0.33, 7.2.34, 7.3.33, 7.4.33, 8.0.30, 8.1.34 |
| `196.192.79.159` | 25 | 7.2.34, 7.3.33, 7.4.33, 8.0.30 |
| `197.149.178.6` | 1 | 8.0.30 |

`154.118.230.167` alone carries seven different PHP branches - it is clearly a
long-lived shared box where each vhost was frozen at whatever version it
deployed with.

The 4 patched hosts sit elsewhere (`www.vpo.go.tz` 8.4.27 on `.254`, plus
`www.metfund.go.tz` and `www.cpaafricaregion.or.tz` 8.2.35 and `www.feta.ac.tz`
8.3.36). So eGA *can* patch - the drift is between boxes, not a capability gap.

## High-value vulnerable hosts

| Host | PHP | What it is |
|---|---|---|
| `www.inec.go.tz` | 8.0.30 | Independent National Electoral Commission |
| `www.nec.go.tz` | 8.0.30 | National Electoral Commission |
| `www.moh.go.tz` | 7.3.33 | Ministry of Health |
| `www.pmo.go.tz` | 7.3.33 | Prime Minister's Office |
| `www.foreign.go.tz` | 7.3.33 | Ministry of Foreign Affairs |
| `www.brela.go.tz` | 7.2.34 | Business registrations agency |
| `www.maji.go.tz` | 7.2.34 | Ministry of Water |
| `lawyers.gov.go.tz` | 5.6.40 | Legal practitioners registry |
| `www.tacaids.go.tz` | 7.2.34 | AIDS commission |
| `www.taa.go.tz`, `www.ncaa.go.tz` | 8.1.34 | Aviation authorities |

## Separate TLS finding

Every one of the 251 hosts shares **one certificate** - CN
`www.vpo.go.tz`, SANs enumerating the whole estate, issued to eGA. All SAN
entries are `www.`-prefixed, so **apex names present a mismatch**:
`https://brela.go.tz/` fails validation (curl exit 60), `https://www.brela.go.tz/`
validates.

`tanzania.go.tz` and `utumishi.go.tz` were separately found serving another
default-vhost certificate, CN `gws-vip.eganet.go.tz`, expiring 2026-11-10.

Practical effect: browsers hard-fail on the apex form, and any tooling that
verifies certificates (curl, most scanners, some API clients) silently skips
these hosts unless told `--insecure`. My first sweep returned all-zeros for
exactly this reason.

## Method note

Targets came from the SAN list of the eGA certificate - an authoritative
inventory of that platform, better than a search-engine scrape. Both apex and
`www.` were checked where relevant; all 54 verdicts were re-confirmed on a
second request and a random sample of 4 reproduced exactly.

## Caveats

- These are `AC:H` memory-corruption bugs. "Vulnerable" means the running
  version is exposed, not that RCE was demonstrated.
- 133 hosts hide their version and could not be graded from outside; the true
  vulnerable count is likely higher than 54.
- Public PoC tooling is calibrated to PHP 8.4.x profiles and fails closed
  elsewhere, so these older branches mostly need bespoke work - though 5.6/7.x
  carry additional well-known bugs of their own.
- eGA's mitigation from php.net (2026-10-23) is worth applying estate-wide now:
  `session.upload_progress.enabled=0`.

## Recommended order

1. Confirm from inside: `php -v` per vhost on `.167` and `.159`.
2. Isolate `.167` first - 28 hosts, seven EOL branches, 5.6.40 included.
3. Fix the certificate: add apex SANs or redirect apex to `www.`.
4. Rebuild on a supported branch (8.3+) rather than stepping one version at a
   time; 5.6 -> 8.x is a rewrite of assumptions, not a patch.
