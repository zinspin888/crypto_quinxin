#!/usr/bin/env python3
"""
PHP version fingerprint scanner - CVE-2026-109618 / CVE-2026-109619 exposure check.

Both CVEs are unauthenticated remote RCE (UAF in the PHP engine), patched in
8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. There is no magic payload to fire at a
random host, so exposure is determined by fingerprinting the running PHP
version and comparing it against those fixed releases.

Passive-first: reads headers/markers only. Extra paths probed only when the
host already looks like PHP. Read-only, no exploitation.

Usage:
    python scan.py --targets targets.txt --out results
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.request

UA = "Mozilla/5.0 (compatible; php-cve-exposure-check/1.0; +nairobi-recon)"
TIMEOUT = 15
MAX_WORKERS = 8

# Fixed releases for GHSA-w8hw-w9fx-j79w (CVE-2026-109618) and
# GHSA-6wmf-4rv5-p3rp (CVE-2026-109619).
PATCHED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

# Extra paths tried only once a host is already known to run PHP.
VERSION_PATHS = ["/phpinfo.php", "/info.php", "/test.php", "/i.php",
                 "/composer.json", "/index.php"]
# Paths that confirm PHP even though they never disclose a version.
PHP_MARKER_PATHS = ["/wp-login.php", "/wp-includes/version.php", "/adminer.php"]

VER_RE = re.compile(r"PHP[/ ]?(\d+\.\d+\.\d+)", re.I)
VERSION_RE = re.compile(r"PHP Version (\d+\.\d+\.\d+)", re.I)
PHPSESSID_RE = re.compile(r"PHPSESSID", re.I)
PHP_HEADER_KEYS = ("server", "x-powered-by", "x-php-version", "php", "via")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def rand_path() -> str:
    return "/__probe_" + "".join(random.choices(string.ascii_lowercase, k=10)) + ".php"


def fetch(url: str) -> dict | None:
    """Single GET. Returns dict or None on transport failure."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=CTX) as r:
            body = r.read(120_000).decode("utf-8", "replace")
            return {"url": url, "final": r.geturl(), "status": r.status,
                    "headers": dict(r.headers.items()), "body": body}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(60_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"url": url, "final": url, "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": body}
    except Exception:
        return None


def parse_version(text: str) -> str | None:
    for rx in (VERSION_RE, VER_RE):
        m = rx.search(text)
        if m:
            return m.group(1)
    return None


def version_tuple(v: str) -> tuple[int, int, int] | None:
    parts = v.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return (int(parts[0]), int(parts[1]), int(parts[2]))



def classify(version: str | None, php_seen: bool) -> str:
    """Map a version (or absence of one) to an exposure verdict."""
    if version:
        t = version_tuple(version)
        if t:
            major, minor, patch = t
            if (major, minor) in PATCHED:
                return "PATCHED" if patch >= PATCHED[(major, minor)] else "VULNERABLE"
            if major == 8:      # 8.0 / 8.1 - EOL, fixes never backported
                return "VULNERABLE"
            if major in (5, 7):  # EOL branches, affected, never patched
                return "VULNERABLE"
            if major > 8:
                return "PATCHED?"
    return "PHP-UNKNOWN-VERSION" if php_seen else "NOT-PHP"


def gather_evidence(host: str) -> dict:
    """Probe one host. Never raises."""
    result: dict = {"host": host, "php_seen": False, "version": None,
                    "evidence": [], "final_url": None, "status": None,
                    "server": None}

    for scheme in ("https", "http"):
        res = fetch(f"{scheme}://{host}/")
        if res is None:
            continue
        result["final_url"] = res["final"]
        result["status"] = res["status"]
        hdrs = {k.lower(): v for k, v in res["headers"].items()}
        result["server"] = hdrs.get("server")

        for key in PHP_HEADER_KEYS:
            val = hdrs.get(key, "")
            if "php" in val.lower():
                result["php_seen"] = True
                result["evidence"].append(f"header {key}: {val}")
                v = parse_version(val)
                if v and not result["version"]:
                    result["version"] = v

        if "set-cookie" in hdrs and PHPSESSID_RE.search(hdrs["set-cookie"]):
            result["php_seen"] = True
            result["evidence"].append("PHPSESSID cookie")

        body = res["body"]
        if "PHPSESSID" in body:
            result["php_seen"] = True
            result["evidence"].append("PHPSESSID in body")

        blob = json.dumps(res["headers"]) + body[:40_000]
        v = parse_version(blob)
        if v:
            result["php_seen"] = True
            result["version"] = v
            result["evidence"].append(f"version disclosed: {v}")
        if re.search(r"PHP (Warning|Fatal error|Parse error)", body):
            result["php_seen"] = True
            result["evidence"].append("PHP error output")

        base = f"{scheme}://{host}"
        # phpinfo leftovers are worth a look even before PHP is confirmed.
        if not result["version"]:
            for path in VERSION_PATHS:
                if result["version"]:
                    break
                sub = fetch(base + path)
                if sub is None:
                    continue
                sv = parse_version(sub["body"])
                if sv:
                    result["php_seen"] = True
                    result["version"] = sv
                    result["evidence"].append(f"{path} -> {sv}")
        # Error verbosity can leak the version in a 404 body.
        if not result["version"] and result["php_seen"]:
            sub = fetch(base + rand_path())
            if sub:
                v = parse_version(sub["body"])
                if v:
                    result["version"] = v
                    result["evidence"].append(f"404 leak -> {v}")
        # App markers that prove PHP without revealing a version.
        if not result["php_seen"]:
            for path in PHP_MARKER_PATHS:
                sub = fetch(base + path)
                if sub and (sub["status"] < 400 or "wp-content" in sub["body"]
                            or "wp-json" in sub["body"]):
                    result["php_seen"] = True
                    result["evidence"].append(f"{path} present (HTTP {sub['status']})")
                    break
            if not result["php_seen"] and ("wp-content" in body or "wp-json" in body):
                result["php_seen"] = True
                result["evidence"].append("WordPress asset paths in body")
            if not result["php_seen"]:
                # /index.php serving 200 means a PHP handler is mapped.
                sub = fetch(base + "/index.php")
                if sub and sub["status"] == 200:
                    result["php_seen"] = True
                    result["evidence"].append("/index.php served (PHP handler present)")
                    v = parse_version(sub["body"])
                    if v:
                        result["version"] = v
                        result["evidence"].append(f"/index.php -> {v}")
        if result["php_seen"] or result["status"]:
            break

    result["verdict"] = classify(result["version"], result["php_seen"])
    return result


def geo(hosts: list[str]) -> dict[str, dict]:
    """Resolve + GeoIP in one batch call. Returns host -> {ip, country, city, isp}."""
    info: dict[str, dict] = {}
    for h in hosts:
        try:
            info[h] = {"ip": socket.gethostbyname(h)}
        except Exception:
            info[h] = {"ip": None}
    ips = sorted({v["ip"] for v in info.values() if v["ip"]})
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=query,countryCode,city,isp",
                data=json.dumps(chunk).encode(),
                headers={"Content-Type": "application/json", "User-Agent": UA},
            )
            with urllib.request.urlopen(req, timeout=25) as r:
                for row in json.loads(r.read().decode()):
                    for h, v in info.items():
                        if v.get("ip") == row.get("query"):
                            v["country"] = row.get("countryCode")
                            v["city"] = row.get("city")
                            v["isp"] = row.get("isp")
        except Exception as e:
            print(f"  ! geoip batch failed: {e}", file=sys.stderr)
        time.sleep(1.6)

    # Fall back to a TLD check when GeoIP gives us nothing usable.
    for h, v in info.items():
        if not v.get("country"):
            if h.endswith((".ke", ".co.ke", ".go.ke", ".ac.ke", ".or.ke")):
                v["country"] = "KE"
            elif h.endswith((".tz", ".co.tz", ".go.tz", ".ac.tz", ".or.tz")):
                v["country"] = "TZ"
            else:
                v["country"] = "??"
    return info


def load_targets(path: str) -> list[tuple[str, str]]:
    out, seen = [], set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            dom, _, cat = line.partition(",")
            dom = dom.strip().lower()
            if dom and dom not in seen:
                seen.add(dom)
                out.append((dom, (cat or "unknown").strip()))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default="targets.txt")
    ap.add_argument("--out", default="results")
    ap.add_argument("--include-non-ke", action="store_true")
    ap.add_argument("--country", default="KE",
                    help="comma-separated ISO country codes to keep (default KE)")
    args = ap.parse_args()

    targets = load_targets(args.targets)
    print(f"[*] {len(targets)} unique targets loaded")

    print("[*] resolving + geolocating")
    geo_map = geo([d for d, _ in targets])

    kept = []
    for dom, cat in targets:
        g = geo_map.get(dom, {})
        cc = g.get("country")
        if not args.include_non_ke and cc not in args.country.split(","):
            print(f"  - skip {dom} (country={cc})")
            continue
        kept.append((dom, cat, g))
    print(f"[*] {len(kept)} Kenya-resolved targets to probe")

    results = []
    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futs = {pool.submit(gather_evidence, d): (d, c, g) for d, c, g in kept}
        for fut in cf.as_completed(futs):
            dom, cat, g = futs[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"host": dom, "php_seen": False, "version": None,
                     "evidence": [f"probe error: {e}"], "verdict": "ERROR"}
            r["category"] = cat
            r.update({k: g.get(k) for k in ("ip", "city", "isp", "country")})
            results.append(r)
            print(f"  {r['verdict']:<20} {dom} {r.get('version') or ''}")

    results.sort(key=lambda r: (r["verdict"] != "VULNERABLE", r["host"]))
    with open(f"{args.out}.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print("\n[*] verdict summary:", json.dumps(counts, sort_keys=True))
    with open(f"{args.out}_summary.json", "w", encoding="utf-8") as f:
        json.dump(counts, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
