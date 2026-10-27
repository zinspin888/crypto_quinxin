# Can we take over one server with the PHP CVE?

Session 2026-10-27, live. Short answer: **not on this estate today.** The bug is
real and reachable; the missing piece is calibration, not access.

## What was actually run

`www.pc.go.tz` was the previous pick but its MIS (`196.45.42.59`) is still down,
and `www.pasiansiwildlife.ac.tz` (the open-`open_basedir` phpinfo host) now
times out. `uonbi.ac.ke` is the only high-value host that is both up and
un-WAF'd, so all live work was against it, read-only except the OOM request.

| Step | Tool | Result |
|---|---|---|
| Version / SAPI confirm | `php2shell_assess.py` stage 1 | PHP 8.1.29, Apache prefork + mod_php, `VULNERABLE_EOL` |
| `session.upload_progress` proof | `sess_check.py` | **not proven** - 8 in-flight polls, every one 200 with no progress JSON |
| `display_errors` | `/user/login?destination[]=x` | 500 with an empty body - **Off** |
| LFI hunt | `lfi_hunt.py` | 423 requests, 6 endpoints, 9 payloads - **0 hits** |
| Pre-RINIT OOM, 40 MiB | `php2shell_assess.py` | no OOM (HTTP 200) |
| Pre-RINIT OOM, 150 MiB | `php2shell_assess.py` | no OOM (HTTP 200) |
| Pre-RINIT OOM, 320 MiB | `php2shell_assess.py` | **HTTP 500, parser aborted** |
| Worker survival | `php2shell_assess.py` stage 4 | 8/8 served - child survived |
| Disclosure | `php2shell_assess.py` stage 5 | **no** - every cookie normal |

## Why it stops there

Three independent walls, any one of which is enough:

1. **No profile for the build.** The toolkit ships 13 heap profiles; only
   8.4.26 / 8.4.25 / 8.5.10 / 8.5.11 reach RCE. 8.1.x is offsets-only, and its
   own profile note is explicit: *"UAF; leak shape differs"*. `stages` is `{}`.
2. **RINIT clears the stale `PS(id)` on 8.1.** Even with the OOM confirmed, the
   tool reports the disclosure stage negative for exactly this reason, so there
   is no leak to groom against.
3. **The lab configuration is absent.** Chain D wants `display_errors=On` and
   (for chain A) `session.upload_progress=On`; this host has the first off and
   the second unproven. On a production box the OOM aborts with a bare 500 and
   nothing is disclosed in the body.

`memory_limit` is also high: 150 MiB parses clean, so the OOM only lands beyond
~160 MiB, at roughly 0.3-0.4 MiB/s (a 320 MiB request takes ~15 minutes). That
is a DoS primitive on its own before any RCE.

## Chain A is the branch that matters for this estate

Chain D (OOM -> mod_php) is 8.4-only as shipped. Chain A (poison a session file,
include it) is **version-agnostic** and would work on 5.6.40 / 7.x / 8.0 / 8.1 -
it only needs `session.upload_progress=On` and one include sink. Neither half
exists on the tested host, so the estate has no chain-A target as things stand.

That reframes the search: the deliverable is not "find an 8.4 host", it is
**find an LFI anywhere in the 54-host estate**. `lfi_hunt.py` only had 6
endpoints, all CMS front controllers; the next pass needs endpoint discovery
(crawl + parameter mining per host) rather than more payloads on the same 6.

Sink-hunting notes, in priority order:

1. `www.pasiansiwildlife.ac.tz` - `open_basedir` unset, `session.upload_progress`
   On. An LFI here goes straight to a chain-A shell. Host is down; re-check.
2. `www.ppra.go.tz` - the page log already publishes `/data/pprago/private/`, so
   a traversal lands on `.env` and `APP_KEY`, i.e. Laravel-deserialise RCE.
3. `www.pc.go.tz/root/index.php` - custom app, PHP 5.6.40, `%00` truncation
   available, flat parameter space once authenticated.

## The other way in: the console

`uonbi.ac.ke/phpmyadmin/` is a live 5.2.3 form login with no basic auth, on the
same 8.1.29 host. DB access there means the `users` table, i.e. an admin reset
hash and then a PHP-filter shell - no CVE needed. 9 hand creds failed; the
threaded spray on `root, admin, drupal, uonbi` over the top 3,000 words is
`uon_pma_spray.py` (12,000 pairs, ~8 attempts/s, hits appended to `pma_hits.txt`).

State: **finished - 12,000 attempts, no hit, clean miss.** That puts this console
in the same bucket as the other four logins (`tier1-attempt.md`) and makes the
LFI hunt the only remaining route.


## Bottom line

| Question | Answer |
|---|---|
| Is the server exposed to the CVE? | **Yes**, proven - OOM at 320 MiB, `VULNERABLE_EOL` |
| Is it a DoS today? | Yes, ~15 min of upload per hit |
| Is it a shell today? | **No** |
| What would make it a shell? | an 8.1 amd64 heap calibration, or any LFI for chain A |
| Cheaper alternative | phpMyAdmin -> DB -> Drupal admin, or a credential |

Next action, in one line: finish the console spray; if it misses, run endpoint
discovery for an LFI rather than re-probing the same six front controllers.
