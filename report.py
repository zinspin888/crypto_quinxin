#!/usr/bin/env python3
"""Render final.json into a markdown exposure report."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

CVE_BLOCK = """\
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
"""


def table(rows: list[dict], cols: list[tuple[str, str]]) -> str:
    if not rows:
        return "_(none)_\n"
    head = "| " + " | ".join(h for h, _ in cols) + " |"
    sep = "|" + "|".join("---" for _ in cols) + "|"
    out = [head, sep]
    for r in rows:
        cells = []
        for _, key in cols:
            v = r.get(key)
            if key == "evidence":
                v = "; ".join(v)[:160] if isinstance(v, list) else v
            cells.append("" if v is None else str(v).replace("|", "\\|"))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else "final.json"
    dst = sys.argv[2] if len(sys.argv) > 2 else "REPORT.md"
    place = sys.argv[3] if len(sys.argv) > 3 else "Nairobi"
    rows = json.load(open(src, encoding="utf-8"))

    vuln = [r for r in rows if r["verdict"] == "VULNERABLE"]
    patched = [r for r in rows if r["verdict"].startswith("PATCHED")]
    unknown = [r for r in rows if r["verdict"] == "PHP-UNKNOWN-VERSION"]

    cols = [("Host", "host"), ("Category", "category"), ("PHP", "version"),
            ("Evidence", "evidence"), ("Resolves to", "ip")]
    pcols = [("Host", "category"), ]

    md = []
    md.append(f"# PHP CVE-2026-109618 / CVE-2026-109619 - {place} exposure report\n")
    md.append(f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC  ")
    md.append(f"Targets probed: {len(rows)} ({place} organisations)\n")
    md.append(CVE_BLOCK)

    md.append("## Headline\n")
    md.append(f"- **Vulnerable PHP confirmed: {len(vuln)}**")
    md.append(f"- Patched already: {len(patched)}")
    md.append(f"- PHP present, version hidden: {len(unknown)}")
    md.append(f"- No PHP observed: {len(rows) - len(vuln) - len(patched) - len(unknown)}\n")

    md.append("## Confirmed vulnerable\n")
    md.append(table(vuln, cols))
    md.append("\n## Confirmed patched\n")
    md.append(table(patched, cols))
    md.append("\n## PHP confirmed, version not disclosed\n")
    md.append(table(unknown, cols))

    md.append("\n## Method\n")
    md.append("""\
Read-only HTTP GETs, ~8 concurrent, 15s timeout, no exploitation.

Version extracted from, in order: `Server` / `X-Powered-By` / `X-PHP-Version`
headers, `phpinfo.php`-style leftovers, PHP error output in 404 bodies, and
`composer.json`. PHP presence additionally inferred from `PHPSESSID` cookies,
`/wp-login.php`, WordPress asset paths and `/index.php` being handled.

Verdicts compare the parsed version against the per-branch fix list; EOL
branches (5.x, 7.x, 8.0, 8.1) are marked vulnerable because these fixes were
never backported to them.
""")

    md.append("\n## Remediation\n")
    md.append("""\
There is no config mitigation that removes the risk - the flaws are in the
engine. Patch PHP, then restart the FPM/Apache workers so the new binary is
actually in use.

```bash
# Debian/Ubuntu (Ondrej Sury PPA / distro packages)
sudo apt-get update && sudo apt-get install --only-upgrade \\
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
""")

    md.append("\n## Caveats\n")

    md.append("""\
1. **Negative is not proof.** A version hidden behind a CDN/WAF cannot be
   graded from outside; `PHP-UNKNOWN-VERSION` needs server-side confirmation
   (`php -v`, package version).
2. **Behind a reverse proxy** the edge PHP may differ from the origin. Test
   the origin directly.
3. `AC:H` means an affected version is *exposed*, not *demonstrably
   exploitable*. Confirming RCE needs the advisory PoCs against a staging clone.
4. Cloudflare/JS-challenged hosts (jumia, safaricom, nation) under-report.
""")
    open(dst, "w", encoding="utf-8").write("\n".join(md))
    print(f"wrote {dst}: {len(vuln)} vulnerable, {len(patched)} patched, {len(unknown)} unknown")
    return 0


if __name__ == "__main__":
    sys.exit(main())
