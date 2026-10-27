#!/usr/bin/env python3
"""Wider artefact sweep with per-extension soft-404 baselines.

finder3 hashed one random '.php' path per host and reused it for every check.
That misses a host which renders a real 404 for PHP but replays the homepage for
unknown extensions. Here every candidate is compared against a fresh random path
carrying the *same* extension (and the same trailing-slash shape for
directories), so a catch-all of any flavour cannot fake a hit.

Nothing is reported on status code alone - content must match a signature.
"""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import json
import random
import re
import string
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

scan.TIMEOUT = 6
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CHECKS = [
    # info / config disclosure
    "/phpinfo.php", "/info.php", "/test.php", "/i.php", "/.env",
    "/.env.local", "/.env.bak", "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/.DS_Store", "/composer.json", "/composer.lock", "/package.json",
    "/sftp-config.json", "/.vscode/sftp.json", "/web.config",
    # archives and dumps
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql",
    "/database.sql", "/site.sql", "/backup/", "/db/", "/sql/", "/old/",
    # consoles / panels
    "/adminer.php", "/adminer/", "/admin/", "/administrator/",
    "/wp-login.php", "/install.php",
    # logs and leftovers
    "/error_log", "/php_errorlog", "/debug.log", "/wp-config.php.bak",
    "/config.php.bak", "/db.php.bak", "/.htpasswd",
    # listings / status
    "/server-status", "/uploads/", "/files/",
]

ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}=.", re.M)
SQL_RE = re.compile(r"(create\s+table|insert\s+into|drop\s+table)", re.I)
PHPERR_RE = re.compile(r"(php (warning|notice|fatal)|on line \d+)", re.I)


def sig(r):
    return (f"{r['status']}:{len(r['body'])}:"
            f"{hashlib.sha1(r['body'][:2000].encode('utf-8', 'replace')).hexdigest()}")


def rnd_for(ext):
    """Random path carrying a given extension (or trailing-slash shape)."""
    stem = "/_q" + "".join(random.choices(string.ascii_lowercase, k=9))
    if ext == "/":
        return stem + "/"
    return stem + ("." + ext if ext else "")


def ext_of(path):
    if path.endswith("/"):
        return "/"
    tail = path.rsplit("/", 1)[-1]
    return tail.rsplit(".", 1)[-1] if "." in tail else ""


def classify(path, body):
    low = body.lower()
    if path in ("/phpinfo.php", "/info.php"):
        if "php version" in low and "loaded configuration file" in low:
            return "phpinfo fully exposed"
        return None
    if path == "/.git/HEAD":
        return "git repo readable" if body.startswith("ref:") else None
    if path == "/.git/config":
        return ("git config leaked" if "[core]" in low
                and "repositoryformatversion" in low else None)
    if path == "/.svn/entries":
        return "svn metadata readable" if re.match(r"^\d+\n", body) else None
    if path == "/.DS_Store":
        return "DS_Store leaked" if body.startswith("\x00\x00\x00\x01Bud1") else None
    if path.startswith("/.env"):
        if "<html" in low[:300]:
            return None
        return "env file leaked" if ENV_RE.search(body) else None
    if path.endswith((".zip", ".tar.gz")):
        if body.startswith("PK"):
            return f"zip archive {len(body)}B"
        if body.startswith("\x1f\x8b"):
            return f"gzip archive {len(body)}B"
        return None
    if path.endswith(".sql"):
        if SQL_RE.search(body):
            return f"SQL dump {len(body)}B"
        if low.lstrip().startswith(("--", "/*", "#")):
            return f"SQL-ish text {len(body)}B"
        return None
    if path == "/server-status":
        return ("server-status live" if "server status" in low
                and "total accesses" in low else None)
    if path in ("/adminer.php", "/adminer/"):
        return "Adminer login page" if "auth[username]" in low else None
    if path.endswith("/"):
        return "directory listing" if "index of /" in low else None
    if path in ("/composer.json", "/composer.lock"):
        return "composer.json leaked" if '"require"' in body else None
    if path == "/package.json":
        return ("package.json leaked" if '"dependencies"' in body
                or ('"name"' in body and '"version"' in body) else None)
    if path.endswith("sftp.json") or path == "/sftp-config.json":
        return ("sftp config leaked" if '"remote_path"' in body
                or "'remote_path'" in body else None)
    if path == "/web.config":
        return "web.config leaked" if "<configuration" in low else None
    if path == "/.htpasswd":
        return ("htpasswd leaked"
                if re.search(r"^\S+:\$(apr1|2y|2a|1)\$", body, re.M) else None)
    if path.endswith(".bak"):
        return ("backup source leaked" if ("db_name" in low or "db_password" in low
                                           or "<?php" in low[:200]) else None)
    if path in ("/error_log", "/php_errorlog", "/debug.log"):
        return "error log leaked" if PHPERR_RE.search(body) else None
    if path in ("/admin/", "/administrator/", "/wp-login.php", "/install.php"):
        if 'type="password"' in low or "type='password'" in low:
            return "live login form"
        return None
    return None


def probe(host):
    out = []
    base = "https://" + host
    b = scan.fetch(base + rnd_for("php"))
    if not b:
        base = "http://" + host
        b = scan.fetch(base + rnd_for("php"))
    if not b:
        return out

    # One soft-404 control per extension, fetched up front and in parallel.
    extents = {ext_of(p) for p in CHECKS}

    def control(ext):
        r = scan.fetch(base + rnd_for(ext))
        return ext, (sig(r) if r else None)

    ctl = {}
    with cf.ThreadPoolExecutor(max_workers=6) as pool:
        for ext, s in pool.map(control, extents):
            ctl[ext] = s

    def check(path):
        bl = ctl.get(ext_of(path))
        if bl is None:
            return None
        r = scan.fetch(base + path)
        if not r or r["status"] == 404 or sig(r) == bl:
            return None
        why = classify(path, r["body"])
        if not why:
            return None
        return {"host": host, "path": path, "status": r["status"], "detail": why}

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        for hit in pool.map(check, CHECKS):
            if hit:
                out.append(hit)
    return out


def main():
    targets = [l.split(",")[0].strip() for l in open(sys.argv[1], encoding="utf-8")
               if l.strip() and not l.startswith("#")]
    res = []
    with cf.ThreadPoolExecutor(max_workers=6) as pool:
        for f in cf.as_completed([pool.submit(probe, h) for h in targets]):
            try:
                res.extend(f.result())
            except Exception as e:
                print("err", e, file=sys.stderr)
    json.dump(res, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
    for r in sorted(res, key=lambda x: (x["host"], x["path"])):
        print(f"  {r['host']}{r['path']} [{r['status']}] {r['detail']}")
    print(f"\n{len(res)} findings across {len(targets)} hosts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
