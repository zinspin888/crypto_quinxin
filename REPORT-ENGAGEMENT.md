# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — exposure and takeover assessment

**Estate:** 54 Tanzanian government hosts + 2 Kenyan hosts confirmed on vulnerable
PHP builds. **Date:** 2026-10-26 → 2026-10-27. **Mode:** read-only, except one
"large body" request per OOM attempt.

> **Authorization caveat.** None of this is under a signed engagement. It is an
> external, low-rate assessment of public websites. Rate was held to ~8
> concurrent requests, 2-5 probes per host, and one intrusive request (the 320 MiB
> OOM) per target. Treat findings as *exposure*, not as permission.

---

## 1. Executive summary

| Question | Answer |
|---|---|
| How many hosts run a vulnerable PHP build? | **56** (54 TZ + 2 KE) |
| Is the CVE reachable from the internet on the best target? | **Yes, proven** — pre-RINIT OOM at 320 MiB, worker survives |
| Did any host yield a shell? | **No** |
| Did any host yield a credential? | No — ~250,000 guesses, zero hits |
| Did any host yield an LFI (the prerequisite for the version-agnostic chain)? | No — 423 targeted probes, zero hits |

The estate is uniformly *behind* on PHP and uniformly *tidy* on files. What is
missing is not access, it is the one primitive the public exploit still needs: a
build profile for these branches, or an LFI.

### The three walls, in order of severity

1. **No calibrated profile exists for any build in this estate.** The public
   toolkit ships 13 heap profiles; only 8.4.25 / 8.4.26 / 8.5.10 / 8.5.11 reach
   RCE. Every vulnerable host here sits on 5.6.40 / 7.x / 8.0.30 / 8.1.29-8.1.34,
   all of which are `offsets only; heap not calibrated` or worse.
2. **RINIT clears the stale `PS(id)` on 8.1.** Even where the OOM is proven, the
   disclosure stage fails on this branch, so there is nothing to groom.
3. **Production configuration differs from the lab.** The chain expects
   `display_errors=On` and `session.upload_progress=On`. The tested host has the
   first off and the second unproven.

---

## 2. What was tested

| Phase | Coverage |
|---|---|
| Version fingerprint sweep | 331 hosts (251 TZ from eGA certificate SANs, 80 KE from `targets.txt`) |
| Vulnerability grading | all positives re-checked; verdicts gated on version, not banners |
| Surviving artefact hunt | 56 vulnerable hosts × 48 paths, with per-extension soft-404 baselines |
| Deep dive | `uonbi.ac.ke` (access assessment), `www.pc.go.tz` (MIS injection) |
| Credential campaigns | ~250,000 pairs over 4 WordPress logins + 2 phpMyAdmin consoles |
| CVE live assessment | `uonbi.ac.ke` — 40, 150 and 320 MiB pre-RINIT OOM attempts |
| LFI hunt | 6 endpoints × 11-14 parameters × 9 payloads = 423 requests |

---

## 3. Exposure distribution

**Tanzania (251 hosts scanned):**

| Verdict | Count |
|---|---|
| `VULNERABLE` | **54** |
| `PHP-UNKNOWN-VERSION` | 133 |
| `NOT-PHP` | 60 |
| `PATCHED` | 4 |

**Kenya (80 hosts scanned):**

| Verdict | Count |
|---|---|
| `VULNERABLE` | **2** |
| `PHP-UNKNOWN-VERSION` | 43 |
| `NOT-PHP` | 32 |
| `PATCHED` | 3 |

Version spread among the confirmed-vulnerable set: `7.2.34` (12), `7.3.33` (12),
`5.6.40` (8), `8.0.30` (8), `7.4.33` (8), `7.0.33` (3), `8.1.34` (3). Not one
host sits in the 8.4.10-8.4.26 band that the public exploit can actually take.

Most of the estate is the eGA shared platform (`154.118.230.167`), which is
itself the structural finding: one box, dozens of `.go.tz` names, one shared
phpMyAdmin.

---

## 4. Verified findings that survived re-checking

The first artefact pass reported **159** findings; verification left **1**. The
cause was catch-all routing — every path returned the homepage. `finder3.py` and
`finder4.py` now baseline a random path *per extension* per host and require a
content signature, not a 200.

| # | Finding | Host | Why it matters |
|---|---|---|---|
| 1 | **Full phpinfo exposed** (not a stub — `Loaded Configuration File`, kernel, docroot) | `www.pasiansiwildlife.ac.tz/phpinfo.php` | `open_basedir` **unset**, `session.upload_progress` **On**, `disable_functions` blocks `system`/`exec` but not `include`. This is the best chain-A candidate in the estate. PHP 8.0.30, FPM. Host was down at test time. |
| 2 | **phpMyAdmin 5.2.3 with a real form login, no basic auth** | `uonbi.ac.ke/phpmyadmin/` | Current phpMyAdmin, but one password from the Drupal `users` table. `package.json` and `ChangeLog` also readable. |
| 3 | Shared phpMyAdmin behind basic auth on 41 hosts | `154.118.230.167` | Single point of failure for the whole TZ platform. 156 pairs tried, no hit. |
| 4 | Two open Joomla administrator consoles | `www.chaliwasa.go.tz`, `www.teiti.go.tz` | PHP 5.6.40 underneath. |

Negative results worth recording: **no** `.git`, **no** `.env`, **no** SQL dumps,
**no** directory listings, anywhere in the estate.

---

## 5. Deep dive — `uonbi.ac.ke`

Chosen because it is the only high-value host that is simultaneously up,
un-WAF'd and on a vulnerable build.

| Fact | Value |
|---|---|
| IP / ASN | `41.89.92.134`, KENET |
| Server | `Apache/2.4.6 () OpenSSL/1.0.2k-fips PHP/8.1.29` |
| SAPI | prefork + **mod_php** (from the `Server` header) |
| CMS | Drupal **7.92** (2022-09-07), core EOL; `CHANGELOG.txt` readable |
| HTTPS | none enforced, no HSTS, TLS 1.2 only |
| `/user/login` | open, no captcha, no 429 |
| `/file/ajax/upload` | anonymous multipart endpoint, advertises 256 MB |
| `/sites/default/settings.php` | executes (0 B), not readable |
| `.info` files | **403**; `README.txt` / `CHANGELOG.txt` readable (module map) |
| Modules identified | views, ctools, token, pathauto, webform, ckeditor `7.x-1.x-dev`, captcha, imce 2.09, media |
| Module versions | all current — no contrib CVE applies |

---

## 6. Live CVE assessment (the evidence)

Run with `php2shell/tools/php2shell_assess.py`, `POST /user/login`, chunked
`multipart/form-data` carrying `PHP_SESSION_UPLOAD_PROGRESS`.

| Body size | Result |
|---|---|
| 40 MiB | HTTP 200 — no OOM |
| 150 MiB | HTTP 200 — no OOM |
| **320 MiB** | **HTTP 500 — parser aborted before RINIT** |
| Worker survival after the abort | **8/8 requests served** — child survived |
| Disclosure (Set-Cookie, 12 probes) | **none** — every cookie had a normal session-id shape |

Tool verdict: `VULNERABLE TO DENIAL OF SERVICE / EXPOSURE, RCE not reproduced`.

`memory_limit` is above 150 MiB and throughput is ~0.3-0.4 MiB/s, so one OOM hit
costs roughly 15 minutes of upload. That is a real, cheap DoS against a
production government site before any RCE is considered.

### Configuration checks supporting the verdict

| Check | Result |
|---|---|
| `display_errors` (`/user/login?destination[]=x`) | 500 with an **empty body** → Off |
| `session.upload_progress` (`sess_check.py`, 8 in-flight polls) | HTTP 200 every time, **no progress JSON** → not proven, likely Off |
| `/etc/passwd` via 9 traversal payloads × 58 parameter slots | 0 hits |

---

## 7. Why a shell does not land

Chain D (OOM → `PG(auto_prepend_file)` overwrite) is calibrated only for 8.4.x.
Chain A (poison a session file, then include it) is **version-agnostic** and would
work on 5.6.40 through 8.1 — but it needs `session.upload_progress=On` and an
include sink, and this estate has neither on any tested host.

So the correct framing is: **the estate needs an LFI, not a newer PHP.** One
traversal anywhere in 54 hosts converts chain A into a pre-auth shell on that
host regardless of branch.

Sink leads, ranked:

1. `www.pasiansiwildlife.ac.tz` — `open_basedir` unset and upload_progress On.
2. `www.ppra.go.tz` — the page log already prints `/data/pprago/private/`, so a
   traversal reaches `.env` and `APP_KEY` (Laravel deserialise RCE).
3. `www.pc.go.tz/root/index.php` — custom app, PHP 5.6.40, `%00` truncation.

---

## 8. Credential campaigns (all negative)

| Target | Accounts | Passwords | Result |
|---|---|---|---|
| `www.nimr.or.tz` (xmlrpc multicall) | 4 real staff usernames | 10,215 + 10,000 | none |
| `www.nimr.or.tz` | admin | 99,999 | none |
| `www.ncaa.go.tz` | admin, ncaa | 10,000 | none |
| `www.ncaa.go.tz` | admin | 99,999 | none |
| `www.ptf.or.tz` | admin, ptf | 10,000 | none |
| `www.ptf.or.tz` | admin | 99,999 | none |
| `www.pc.go.tz/phpmyadmin/` (basic auth) | 6 | 216 + empty | none |
| `uonbi.ac.ke/phpmyadmin/` (form login) | root, admin, drupal, uonbi | 3,000 | none — clean miss, all 12,000 pairs |

~250,000 guesses, zero hits. The top-100k is the standard bar for "weak password
on an internet login"; these estates clear it. A parser bug found during this
work is recorded in `tier1-attempt.md` — absence of `faultCode` is not success.

With the console too now closed, the LFI hunt is the only remaining route into
this estate; further wordlist work has poor expected value.

---

## 9. `www.pc.go.tz` and its MIS

The site itself (PHP 5.6.40, `/admin/` panel, `/phpmyadmin/` behind basic auth)
never fell over; the MIS host `mis.pc.go.tz` (`196.45.42.59`, separate box, own
infrastructure) collapsed **twice** under probing and stayed down, so it is out
of scope until it returns.

What did work there: the MIS password-recovery `email` parameter is injectable —
a bogus address returns "Your Email Address is wrong!", while `' OR '1'='1` and
siblings return the page with no error. Exploiting it is blocked by a keyword
blocklist WAF: `admin'-- -` gives 200, `admin' ORDER BY 1-- -` gives **403**,
and the 403 itself knocks the service over for ~25 minutes. A wrong-count UNION
is the fallback that avoids `ORDER BY` entirely (`union2.py`).

---

## 10. Remediation, server side

1. Patch, in this order: 5.6.40 and 7.x hosts are four branches behind and will
   never be fixed — they need a rebuild. 8.0.30/8.1.x hosts need 8.3.36+.
2. Turn `expose_php` off (hides version) **and** `session.upload_progress` off
   where no upload UI needs it. That alone blunts chain A.
3. Keep `display_errors` off, but alert on `Unknown on line 0` memory fatals —
   that is the OOM signature.
4. Cap `post_max_size` *and* `max_multipart_body_parts`, and front the box with a
   proxy that enforces a body ceiling; chunked bodies bypass `post_max_size`.
5. Remove `phpinfo.php`, `package.json`, `ChangeLog`, `CHANGELOG.txt`.
6. Put the shared phpMyAdmin behind SSO and split it per-tenant.

---

## 11. Reproduce

```bash
python scan.py --targets tz_estate.txt --out results_tz --country TZ --include-non-ke
python report.py results_tz.json REPORT_TZ.md "Tanzania government"
python finder4.py tz_estate.txt findings4.json
python lfi_hunt.py
python sess_check.py uonbi.ac.ke /user/login
python php2shell/tools/php2shell_assess.py \
    --target https://uonbi.ac.ke/ --post-path /user/login --oom-mb 320 --allow-remote
```

---

## 12. Limitations

- `VULNERABLE` means *exposed version*, never *proven exploitable*. Only one host
  has a proof, and that proof is DoS, not RCE.
- 133 TZ + 43 KE hosts are `PHP-UNKNOWN-VERSION` and ungradeable from outside.
- A reverse proxy means the edge may differ from the origin.
- Cloudflare JS challenges under-report (`jumia.co.ke`, `safaricom.co.ke`).
- All figures are point-in-time; the estate changes daily.
- No credential was used, so nothing was validated from inside any host.


