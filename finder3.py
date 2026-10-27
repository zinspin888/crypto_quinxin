#!/usr/bin/env python3
"""Fast variant: short timeout, trimmed checks, content-sniffed only."""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import json
import random
import string
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

scan.TIMEOUT = 6
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CHECKS = ["/phpinfo.php", "/.env", "/.git/HEAD", "/backup.zip", "/db.sql",
          "/adminer.php", "/server-status", "/uploads/", "/admin/",
          "/wp-login.php", "/install.php", "/composer.json"]


def sig(r):
    return (f"{r['status']}:{len(r['body'])}:"
            f"{hashlib.sha1(r['body'][:2000].encode('utf-8', 'replace')).hexdigest()}")


def rnd(ext):
    return "/_q" + "".join(random.choices(string.ascii_lowercase, k=8)) + ext


def classify(path, body):
    low = body.lower()
    if path == "/phpinfo.php":
        if "php version" in low and "loaded configuration file" in low:
            return "phpinfo fully exposed"
    elif path == "/.git/HEAD":
        return "git repo readable" if body.startswith("ref:") else None
    elif path == "/.env":
        if "<html" not in low[:300] and "=" in body:
            return "env file leaked"
    elif path.endswith((".zip", ".sql")):
        if body.startswith("PK"):
            return f"zip archive {len(body)}B"
        if low.lstrip().startswith(("--", "/*", "#")) or "create table" in low:
            return f"SQL dump {len(body)}B"
    elif path == "/server-status":
        return "server-status live" if "server status" in low else None
    elif path == "/adminer.php":
        if "adminer" in low and "auth[username]" in low:
            return "Adminer login page"
    elif path == "/uploads/":
        return "directory listing" if "index of" in low else None
    elif path == "/composer.json":
        return "composer.json leaked" if '"require"' in body else None
    return None


def probe(host):
    out = []
    base = "https://" + host
    b = scan.fetch(base + rnd(".php"))
    if not b:
        base = "http://" + host
        b = scan.fetch(base + rnd(".php"))
    if not b:
        return out
    bsig = sig(b)
    for path in CHECKS:
        r = scan.fetch(base + path)
        if not r or r["status"] == 404 or sig(r) == bsig:
            continue
        why = classify(path, r["body"])
        if why:
            out.append({"host": host, "path": path, "status": r["status"],
                        "detail": why})
    return out


def main():
    targets = [l.split(",")[0].strip() for l in open(sys.argv[1], encoding="utf-8")
               if l.strip() and not l.startswith("#")]
    res = []
    with cf.ThreadPoolExecutor(max_workers=10) as pool:
        for f in cf.as_completed([pool.submit(probe, h) for h in targets]):
            try:
                res.extend(f.result())
            except Exception as e:
                print("err", e, file=sys.stderr)
    json.dump(res, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
    for r in sorted(res, key=lambda x: x["host"]):
        print(f"  {r['host']}{r['path']} [{r['status']}] {r['detail']}")
    print(f"\n{len(res)} findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
