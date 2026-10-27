#!/usr/bin/env python3
"""Hunt for high-value exposed artefacts across a target list.

Runs only against hosts already confirmed vulnerable, so the request budget is
spent where a foothold would actually matter. Also probes common app
subdomains, since certificate SANs never list those.

Usage: python finder.py targets.txt out.json
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# path -> (label, weight, verifier)
CHECKS = [
    ("/phpinfo.php", "phpinfo", 6),
    ("/info.php", "phpinfo-stub", 3),
    ("/.git/HEAD", "git-repo", 6),
    ("/.env", "dotenv", 6),
    ("/backup.zip", "backup-zip", 4),
    ("/db.sql", "db-dump", 5),
    ("/.DS_Store", "ds_store", 2),
    ("/composer.json", "composer", 2),
    ("/server-status", "server-status", 4),
    ("/adminer.php", "adminer", 4),
    ("/phpmyadmin/", "phpmyadmin", 2),
    ("/admin/", "admin-panel", 3),
    ("/administrator/", "joomla-admin", 3),
    ("/user/login", "drupal-login", 2),
    ("/wp-login.php", "wp-login", 2),
    ("/install.php", "installer", 2),
    ("/xmlrpc.php", "xmlrpc", 1),
    ("/.htpasswd", "htpasswd", 3),
    ("/uploads/", "uploads-dir", 3),
    ("/files/", "files-dir", 2),
]

SUBS = ["mis", "portal", "eportal", "erp", "app", "admin", "staff", "webmail", "intranet"]


def content_signal(path: str, r: dict) -> tuple[bool, str]:
    """Decide whether a 2xx/403 response is genuinely interesting."""
    body = r["body"]
    low = body.lower()
    st = r["status"]
    if st >= 400:
        # 403 on a directory is not a finding by itself
        return (path in ("/server-status", "/.htpasswd"), f"HTTP {st}")
    if path == "/phpinfo.php" and "php version" in low:
        keys = [k for k in ("Loaded Configuration File", "DOCUMENT_ROOT",
                            "disable_functions", "open_basedir") if k in body]
        return True, f"phpinfo exposed ({', '.join(keys) or 'no config keys'})"
    if path == "/.git/HEAD" and body.startswith("ref:"):
        return True, "git repository readable"
    if path == "/.env" and "=" in body and len(body) < 40000:
        names = [ln.split("=")[0] for ln in body.splitlines()
                 if "=" in ln and not ln.strip().startswith("#")][:6]
        return True, f".env leaked ({', '.join(names)})"
    if path in ("/backup.zip", "/db.sql") and len(body) > 1000:
        return True, f"{len(body)} bytes returned"
    if path in ("/admin/", "/administrator/", "/adminer.php", "/phpmyadmin/"):
        return True, f"HTTP {st}, {len(body)} bytes"
    if path == "/server-status" and "server status" in low:
        return True, "Apache server-status exposed"
    if path in ("/uploads/", "/files/") and "index of" in low:
        return True, "directory listing"
    if path in ("/install.php", "/user/login", "/wp-login.php"):
        return True, f"HTTP {st}"
    if path == "/xmlrpc.php" and st == 200:
        return True, "xmlrpc live"
    if path == "/composer.json" and "require" in low:
        return True, "composer.json leaked"
    return False, ""


def probe(host: str) -> list[dict]:
    out = []
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}"
        hit = False
        for path, label, weight in CHECKS:
            r = scan.fetch(base + path)
            if not r:
                continue
            hit = True
            ok, why = content_signal(path, r)
            if ok:
                out.append({"host": host, "path": path, "label": label,
                            "weight": weight, "detail": why})
        # PHP error verbosity: does a bogus .php leak a path?
        r = scan.fetch(base + "/__nope_" + "z" * 8 + ".php")
        if r and r["status"] >= 500 and ("Fatal error" in r["body"]
                                         or "Warning" in r["body"]):
            out.append({"host": host, "path": "(500 page)", "label": "verbose-errors",
                        "weight": 3, "detail": "PHP error text with paths"})
        if hit:
            break
    return out


def subs(host: str) -> list[dict]:
    out = []
    apex = ".".join(host.split(".")[1:]) if host.startswith("www.") else host
    for s in SUBS:
        name = f"{s}.{apex}"
        try:
            import socket
            socket.gethostbyname(name)
        except Exception:
            continue
        r = scan.fetch(f"https://{name}/")
        if not r:
            r = scan.fetch(f"http://{name}/")
        if r and r["status"] < 500:
            out.append({"host": name, "path": "/", "label": "subdomain",
                        "weight": 2, "detail": f"live, HTTP {r['status']}, "
                                               f"{len(r['body'])} bytes"})
    return out


def main() -> int:
    targets = [ln.split(",")[0].strip() for ln in open(sys.argv[1], encoding="utf-8")
               if ln.strip() and not ln.startswith("#")]
    dst = sys.argv[2] if len(sys.argv) > 2 else "findings.json"
    results: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=6) as pool:
        futs = []
        for h in targets:
            futs.append(pool.submit(probe, h))
            futs.append(pool.submit(subs, h))
        for f in cf.as_completed(futs):
            try:
                results.extend(f.result())
            except Exception as e:
                print("err:", e, file=sys.stderr)
    results.sort(key=lambda r: (-r["weight"], r["host"]))
    json.dump(results, open(dst, "w", encoding="utf-8"), indent=2)
    for r in results:
        print(f"  [{r['weight']}] {r['host']}{r['path']}  {r['label']}: {r['detail']}")
    print(f"\n{len(results)} findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
